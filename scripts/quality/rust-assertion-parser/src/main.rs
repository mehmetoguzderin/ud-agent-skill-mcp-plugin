//! Parse trusted Rust source without compiling or executing the supplied program.
mod cfg_regions;
use std::io::{self, Read};
use syn::{
    Attribute, Expr, Item, Meta, Token,
    parse::Parser,
    punctuated::Punctuated,
    spanned::Spanned,
    visit::{self, Visit},
};

// Evaluate cfg with test=false and all other atoms unknown. Only a definitely
// false expression proves that the containing item requires the test build.
fn without_test(meta: &Meta) -> Option<bool> {
    match meta {
        Meta::Path(path) if path.is_ident("test") => Some(false),
        Meta::List(list) => {
            let children = Punctuated::<Meta, Token![,]>::parse_terminated
                .parse2(list.tokens.clone())
                .ok()?;
            if list.path.is_ident("not") && children.len() == 1 {
                return without_test(children.first()?).map(|value| !value);
            }
            if list.path.is_ident("all") {
                if children
                    .iter()
                    .any(|child| without_test(child) == Some(false))
                {
                    return Some(false);
                }
                if children
                    .iter()
                    .all(|child| without_test(child) == Some(true))
                {
                    return Some(true);
                }
            }
            if list.path.is_ident("any") {
                if children
                    .iter()
                    .any(|child| without_test(child) == Some(true))
                {
                    return Some(true);
                }
                if children
                    .iter()
                    .all(|child| without_test(child) == Some(false))
                {
                    return Some(false);
                }
            }
            None
        }
        _ => None,
    }
}

fn test_only(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("cfg")
            && attribute
                .parse_args::<Meta>()
                .ok()
                .is_some_and(|meta| without_test(&meta) == Some(false))
    })
}

#[derive(Default)]
struct Collector {
    test_scope: bool,
    modules: Vec<String>,
    sites: Vec<serde_json::Value>,
    tests: Vec<String>,
    external_modules: Vec<serde_json::Value>,
}

impl<'ast> Visit<'ast> for Collector {
    fn visit_item(&mut self, item: &'ast Item) {
        let attributes: &[Attribute] = match item {
            Item::Const(value) => &value.attrs,
            Item::Enum(value) => &value.attrs,
            Item::ExternCrate(value) => &value.attrs,
            Item::Fn(value) => &value.attrs,
            Item::ForeignMod(value) => &value.attrs,
            Item::Impl(value) => &value.attrs,
            Item::Macro(value) => &value.attrs,
            Item::Mod(value) => &value.attrs,
            Item::Static(value) => &value.attrs,
            Item::Struct(value) => &value.attrs,
            Item::Trait(value) => &value.attrs,
            Item::TraitAlias(value) => &value.attrs,
            Item::Type(value) => &value.attrs,
            Item::Union(value) => &value.attrs,
            Item::Use(value) => &value.attrs,
            _ => &[],
        };
        let previous = self.test_scope;
        self.test_scope |= test_only(attributes);
        visit::visit_item(self, item);
        self.test_scope = previous;
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        let previous = self.test_scope;
        if item
            .attrs
            .iter()
            .any(|attribute| attribute.path().is_ident("test"))
        {
            let mut name = self.modules.clone();
            name.push(item.sig.ident.to_string());
            self.tests.push(name.join("::"));
            self.test_scope = true;
        }
        visit::visit_item_fn(self, item);
        self.test_scope = previous;
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        self.modules.push(item.ident.to_string());
        if item.content.is_none() {
            let mut explicit = None;
            for attribute in &item.attrs {
                if attribute.path().is_ident("path") {
                    if let Meta::NameValue(value) = &attribute.meta {
                        if let Expr::Lit(literal) = &value.value {
                            if let syn::Lit::Str(string) = &literal.lit {
                                explicit = Some(string.value());
                            }
                        }
                    }
                }
            }
            self.external_modules.push(serde_json::json!({"modules": self.modules, "path": explicit, "test_only": self.test_scope}));
        }
        visit::visit_item_mod(self, item);
        self.modules.pop();
    }

    fn visit_macro(&mut self, value: &'ast syn::Macro) {
        if self.test_scope && value.path.segments.len() <= 2 {
            let name = value
                .path
                .segments
                .last()
                .map(|part| part.ident.to_string())
                .unwrap_or_default();
            let namespace = value
                .path
                .segments
                .first()
                .map(|part| part.ident.to_string())
                .unwrap_or_default();
            if [
                "assert",
                "assert_eq",
                "assert_ne",
                "debug_assert",
                "debug_assert_eq",
                "debug_assert_ne",
            ]
            .contains(&name.as_str())
                && (value.path.segments.len() == 1 || namespace == "std" || namespace == "core")
            {
                let point = value.path.span().start();
                self.sites.push(serde_json::json!({"line": point.line, "column": point.column + 1, "macro": name}));
            }
        }
        visit::visit_macro(self, value);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments != ["--source"]
        && arguments != ["--source", "--test-scope"]
        && arguments != ["--cfg-regions"]
    {
        return Err("invalid parser arguments".into());
    }
    let mut bytes = Vec::new();
    io::stdin()
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err("Rust source exceeds parser bound".into());
    }
    let source = std::str::from_utf8(&bytes)?;
    let syntax = syn::parse_file(source)?;
    if arguments == ["--cfg-regions"] {
        println!(
            "{}",
            cfg_regions::collect(&syntax).map_err(io::Error::other)?
        );
        return Ok(());
    }
    let mut collector = Collector {
        test_scope: arguments.len() == 2,
        ..Default::default()
    };
    collector.visit_file(&syntax);
    println!(
        "{}",
        serde_json::json!({"schema_version": 1, "sites": collector.sites, "tests": collector.tests, "external_modules": collector.external_modules})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(source: &str, test_scope: bool) -> Collector {
        let file = syn::parse_file(source).expect("fixture is valid Rust syntax");
        let mut collector = Collector {
            test_scope,
            ..Default::default()
        };
        collector.visit_file(&file);
        collector
    }

    #[test]
    fn strings_comments_and_production_macros_are_not_assertion_sites() {
        let result = collect(
            "// assert!(false);\nfn ordinary(){ let _ = \"assert_eq!(1,2)\"; assert!(true); }\n#[test]\nfn actual(){ assert_eq!(1,2); }",
            false,
        );
        assert_eq!(result.tests, ["actual"]);
        assert_eq!(
            result.sites,
            [serde_json::json!({"line":4,"column":14,"macro":"assert_eq"})]
        );
    }

    #[test]
    fn nested_test_helpers_and_qualified_builtins_keep_exact_locations() {
        let result = collect(
            "#[cfg(test)] mod tests { fn helper(){std::assert_ne!(1,2);} #[test] fn check(){helper();} }",
            false,
        );
        assert_eq!(result.tests, ["tests::check"]);
        assert_eq!(result.sites.len(), 1);
        assert_eq!(
            result.sites[0],
            serde_json::json!({"line":1,"column":38,"macro":"assert_ne"})
        );
    }

    #[test]
    fn cfg_requires_test_rather_than_merely_mentioning_it() {
        for (attribute, expected) in [
            ("test", 1),
            ("all(test,unix)", 1),
            ("all(unix,test)", 1),
            ("not(not(test))", 1),
            ("any(test,unix)", 0),
            ("not(test)", 0),
            ("all(unix,not(test))", 0),
            ("any()", 1),
            ("all()", 0),
        ] {
            let result = collect(
                &format!("#[cfg({attribute})] fn helper(){{assert!(true);}}"),
                false,
            );
            assert_eq!(result.sites.len(), expected, "cfg {attribute}");
        }
    }

    #[test]
    fn integration_scope_includes_helpers_but_not_custom_macro_namespaces() {
        let result = collect(
            "fn helper(){ assert!(true); core::debug_assert_eq!(1,1); foreign::assert!(false); panic!(\"assertion failed\"); }",
            true,
        );
        assert_eq!(result.sites.len(), 2);
        assert_eq!(result.sites[0]["macro"], "assert");
        assert_eq!(result.sites[1]["macro"], "debug_assert_eq");
        assert!(result.tests.is_empty());
    }

    #[test]
    fn external_module_paths_and_inherited_test_scope_are_explicit() {
        let result = collect(
            "mod top { #[cfg(test)] #[path=\"other.rs\"] mod nested; } mod plain;",
            false,
        );
        assert_eq!(
            result.external_modules,
            [
                serde_json::json!({"modules":["top","nested"],"path":"other.rs","test_only":true}),
                serde_json::json!({"modules":["plain"],"path":null,"test_only":false})
            ]
        );
    }

    #[test]
    fn test_scope_is_restored_after_each_module_and_function() {
        let result = collect(
            "#[test] fn one(){ assert!(true); } fn outside(){assert!(false);} #[cfg(test)] mod nested { fn inside(){assert!(true);} } fn last(){assert!(false);}",
            false,
        );
        assert_eq!(result.sites.len(), 2);
        assert_eq!(result.tests, ["one"]);
    }

    #[test]
    fn unicode_names_and_source_columns_are_preserved() {
        let result = collect(
            "mod δοκιμή { #[test] fn 測試(){ assert_ne!(1,2); } }",
            false,
        );
        assert_eq!(result.tests, ["δοκιμή::測試"]);
        assert_eq!(result.sites[0]["column"], 31);
    }
}
