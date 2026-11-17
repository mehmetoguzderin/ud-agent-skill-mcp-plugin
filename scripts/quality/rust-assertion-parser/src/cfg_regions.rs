//! Source regions governed by Rust's cfg grammar, without compiling input code.
use serde_json::{Value, json};
use syn::{
    Attribute, Expr, Item, Meta, Token,
    ext::IdentExt,
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
    spanned::Spanned,
    visit::{self, Visit},
};

fn flag(name: &str) -> Value {
    json!({"kind":"flag","name":name})
}
fn all(items: Vec<Value>) -> Value {
    json!({"kind":"all","items":items})
}
fn any(items: Vec<Value>) -> Value {
    json!({"kind":"any","items":items})
}
fn not(item: Value) -> Value {
    json!({"kind":"not","item":item})
}
struct Predicate(Value);
impl Parse for Predicate {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.peek(syn::LitBool) {
            let value = input.parse::<syn::LitBool>()?;
            return Ok(Self(if value.value {
                all(vec![])
            } else {
                any(vec![])
            }));
        }
        let name = input.call(syn::Ident::parse_any)?.unraw().to_string();
        if input.peek(Token![=]) {
            input.parse::<Token![=]>()?;
            let value = input.parse::<syn::LitStr>()?;
            return Ok(Self(
                json!({"kind":"value","name":name,"value":value.value()}),
            ));
        }
        if input.peek(syn::token::Paren) {
            let content;
            syn::parenthesized!(content in input);
            let values = Punctuated::<Predicate, Token![,]>::parse_terminated(&content)?
                .into_iter()
                .map(|p| p.0)
                .collect::<Vec<_>>();
            return match name.as_str() {
                "all" => Ok(Self(all(values))),
                "any" => Ok(Self(any(values))),
                "not" if values.len() == 1 => Ok(Self(not(values.into_iter().next().unwrap()))),
                _ => Err(input.error("unsupported cfg predicate operator/arity")),
            };
        }
        Ok(Self(flag(&name)))
    }
}
struct OnePredicate(Value);
impl Parse for OnePredicate {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let value = input.parse::<Predicate>()?.0;
        if input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
        }
        Ok(Self(value))
    }
}
struct ConditionalAttributes {
    predicate: Value,
    attributes: Vec<Meta>,
}
impl Parse for ConditionalAttributes {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let predicate = input.parse::<Predicate>()?.0;
        input.parse::<Token![,]>()?;
        let attributes = Punctuated::<Meta, Token![,]>::parse_terminated(input)?
            .into_iter()
            .collect::<Vec<_>>();
        if attributes.is_empty() {
            return Err(input.error("cfg_attr requires an attribute"));
        }
        Ok(Self {
            predicate,
            attributes,
        })
    }
}
fn attributes(attributes: &[Attribute]) -> Result<Vec<Value>, String> {
    fn descend(meta: &Meta, when: Value, out: &mut Vec<Value>) -> Result<(), String> {
        if (meta.path().is_ident("cfg") || meta.path().is_ident("cfg_attr"))
            && !matches!(meta, Meta::List(_))
        {
            return Err("cfg/cfg_attr requires its parenthesized grammar".into());
        }
        if let Meta::List(value) = meta {
            if value.path.is_ident("cfg") {
                let predicate = syn::parse2::<OnePredicate>(value.tokens.clone())
                    .map_err(|error| error.to_string())?
                    .0;
                out.push(any(vec![not(when), predicate]));
            } else if value.path.is_ident("cfg_attr") {
                let children = syn::parse2::<ConditionalAttributes>(value.tokens.clone())
                    .map_err(|error| error.to_string())?;
                let when = all(vec![when, children.predicate]);
                for child in &children.attributes {
                    descend(child, when.clone(), out)?;
                }
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    for attr in attributes {
        descend(&attr.meta, all(vec![]), &mut out)?;
    }
    Ok(out)
}
fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(v) => &v.attrs,
        Item::Enum(v) => &v.attrs,
        Item::ExternCrate(v) => &v.attrs,
        Item::Fn(v) => &v.attrs,
        Item::ForeignMod(v) => &v.attrs,
        Item::Impl(v) => &v.attrs,
        Item::Macro(v) => &v.attrs,
        Item::Mod(v) => &v.attrs,
        Item::Static(v) => &v.attrs,
        Item::Struct(v) => &v.attrs,
        Item::Trait(v) => &v.attrs,
        Item::TraitAlias(v) => &v.attrs,
        Item::Type(v) => &v.attrs,
        Item::Union(v) => &v.attrs,
        Item::Use(v) => &v.attrs,
        _ => &[],
    }
}
fn expr_attrs(expr: &Expr) -> &[Attribute] {
    match expr {
        Expr::Array(v) => &v.attrs,
        Expr::Assign(v) => &v.attrs,
        Expr::Async(v) => &v.attrs,
        Expr::Await(v) => &v.attrs,
        Expr::Binary(v) => &v.attrs,
        Expr::Block(v) => &v.attrs,
        Expr::Break(v) => &v.attrs,
        Expr::Call(v) => &v.attrs,
        Expr::Cast(v) => &v.attrs,
        Expr::Closure(v) => &v.attrs,
        Expr::Const(v) => &v.attrs,
        Expr::Continue(v) => &v.attrs,
        Expr::Field(v) => &v.attrs,
        Expr::ForLoop(v) => &v.attrs,
        Expr::Group(v) => &v.attrs,
        Expr::If(v) => &v.attrs,
        Expr::Index(v) => &v.attrs,
        Expr::Infer(v) => &v.attrs,
        Expr::Let(v) => &v.attrs,
        Expr::Lit(v) => &v.attrs,
        Expr::Loop(v) => &v.attrs,
        Expr::Macro(v) => &v.attrs,
        Expr::Match(v) => &v.attrs,
        Expr::MethodCall(v) => &v.attrs,
        Expr::Paren(v) => &v.attrs,
        Expr::Path(v) => &v.attrs,
        Expr::Range(v) => &v.attrs,
        Expr::RawAddr(v) => &v.attrs,
        Expr::Reference(v) => &v.attrs,
        Expr::Repeat(v) => &v.attrs,
        Expr::Return(v) => &v.attrs,
        Expr::Struct(v) => &v.attrs,
        Expr::Try(v) => &v.attrs,
        Expr::TryBlock(v) => &v.attrs,
        Expr::Tuple(v) => &v.attrs,
        Expr::Unary(v) => &v.attrs,
        Expr::Unsafe(v) => &v.attrs,
        Expr::While(v) => &v.attrs,
        Expr::Yield(v) => &v.attrs,
        _ => &[],
    }
}
fn span(value: impl Spanned) -> Value {
    let span = value.span();
    let start = span.start();
    let end = span.end();
    json!({"start":{"line":start.line,"column":start.column+1},"end":{"line":end.line,"column":end.column+1}})
}
fn condition(expr: &Expr) -> Result<(Value, bool), String> {
    match expr {
        Expr::Macro(value) if value.mac.path.is_ident("cfg") => {
            let predicate = syn::parse2::<OnePredicate>(value.mac.tokens.clone())
                .map_err(|error| error.to_string())?
                .0;
            Ok((predicate, true))
        }
        Expr::Paren(v) => condition(&v.expr),
        Expr::Group(v) => condition(&v.expr),
        Expr::Unary(v) if matches!(v.op, syn::UnOp::Not(_)) => {
            let (value, found) = condition(&v.expr)?;
            Ok((not(value), found))
        }
        Expr::Binary(v) if matches!(v.op, syn::BinOp::And(_) | syn::BinOp::Or(_)) => {
            let (a, af) = condition(&v.left)?;
            let (b, bf) = condition(&v.right)?;
            Ok((
                if matches!(v.op, syn::BinOp::And(_)) {
                    all(vec![a, b])
                } else {
                    any(vec![a, b])
                },
                af || bf,
            ))
        }
        Expr::Lit(v) => {
            if let syn::Lit::Bool(value) = &v.lit {
                Ok((
                    if value.value {
                        all(vec![])
                    } else {
                        any(vec![])
                    },
                    false,
                ))
            } else {
                Ok((json!({"kind":"unknown"}), false))
            }
        }
        _ => Ok((json!({"kind":"unknown"}), false)),
    }
}
#[derive(Default)]
struct Collector {
    guards: Vec<Value>,
    modules: Vec<String>,
    regions: Vec<Value>,
    external: Vec<Value>,
    error: Option<String>,
}
impl Collector {
    fn enter(&mut self, attrs: &[Attribute], node: impl Spanned) -> usize {
        let size = self.guards.len();
        match attributes(attrs) {
            Ok(values) => {
                if !values.is_empty() {
                    self.guards.extend(values);
                    self.regions
                        .push(json!({"span":span(node),"predicate":all(self.guards.clone())}));
                }
            }
            Err(error) => self.error = Some(error),
        }
        size
    }
    fn branch(&mut self, node: impl Spanned, condition: Value) {
        let mut guards = self.guards.clone();
        guards.push(condition);
        self.regions
            .push(json!({"span":span(node),"predicate":all(guards)}));
    }
}
impl<'ast> Visit<'ast> for Collector {
    fn visit_item(&mut self, node: &'ast Item) {
        let previous = self.enter(item_attrs(node), node);
        visit::visit_item(self, node);
        self.guards.truncate(previous);
    }
    fn visit_local(&mut self, node: &'ast syn::Local) {
        let previous = self.enter(&node.attrs, node);
        visit::visit_local(self, node);
        self.guards.truncate(previous);
    }
    fn visit_expr(&mut self, node: &'ast Expr) {
        let previous = self.enter(expr_attrs(node), node);
        visit::visit_expr(self, node);
        self.guards.truncate(previous);
    }
    fn visit_field(&mut self, node: &'ast syn::Field) {
        let previous = self.enter(&node.attrs, node);
        visit::visit_field(self, node);
        self.guards.truncate(previous);
    }
    fn visit_variant(&mut self, node: &'ast syn::Variant) {
        let previous = self.enter(&node.attrs, node);
        visit::visit_variant(self, node);
        self.guards.truncate(previous);
    }
    fn visit_impl_item(&mut self, node: &'ast syn::ImplItem) {
        let attrs = match node {
            syn::ImplItem::Const(v) => &v.attrs,
            syn::ImplItem::Fn(v) => &v.attrs,
            syn::ImplItem::Type(v) => &v.attrs,
            syn::ImplItem::Macro(v) => &v.attrs,
            _ => return visit::visit_impl_item(self, node),
        };
        let previous = self.enter(attrs, node);
        visit::visit_impl_item(self, node);
        self.guards.truncate(previous);
    }
    fn visit_trait_item(&mut self, node: &'ast syn::TraitItem) {
        let attrs = match node {
            syn::TraitItem::Const(v) => &v.attrs,
            syn::TraitItem::Fn(v) => &v.attrs,
            syn::TraitItem::Type(v) => &v.attrs,
            syn::TraitItem::Macro(v) => &v.attrs,
            _ => return visit::visit_trait_item(self, node),
        };
        let previous = self.enter(attrs, node);
        visit::visit_trait_item(self, node);
        self.guards.truncate(previous);
    }
    fn visit_foreign_item(&mut self, node: &'ast syn::ForeignItem) {
        let attrs = match node {
            syn::ForeignItem::Fn(v) => &v.attrs,
            syn::ForeignItem::Static(v) => &v.attrs,
            syn::ForeignItem::Type(v) => &v.attrs,
            syn::ForeignItem::Macro(v) => &v.attrs,
            _ => return visit::visit_foreign_item(self, node),
        };
        let previous = self.enter(attrs, node);
        visit::visit_foreign_item(self, node);
        self.guards.truncate(previous);
    }
    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        match condition(&node.cond) {
            Ok((predicate, true)) => {
                self.branch(&node.then_branch, predicate.clone());
                if let Some((_, otherwise)) = &node.else_branch {
                    self.branch(otherwise.as_ref(), not(predicate.clone()));
                }
                self.visit_expr(&node.cond);
                self.guards.push(predicate.clone());
                self.visit_block(&node.then_branch);
                self.guards.pop();
                if let Some((_, otherwise)) = &node.else_branch {
                    self.guards.push(not(predicate));
                    self.visit_expr(otherwise);
                    self.guards.pop();
                }
                return;
            }
            Err(error) => self.error = Some(error),
            _ => {}
        }
        visit::visit_expr_if(self, node);
    }
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        self.modules.push(node.ident.unraw().to_string());
        if node.content.is_none() {
            fn paths(meta: &Meta, when: Value, out: &mut Vec<Value>) -> Result<(), String> {
                if let Meta::NameValue(value) = meta {
                    if value.path.is_ident("path") {
                        if let Expr::Lit(lit) = &value.value {
                            if let syn::Lit::Str(path) = &lit.lit {
                                out.push(json!({"predicate":when,"path":path.value()}));
                                return Ok(());
                            }
                        }
                        return Err("module path must be a string literal".into());
                    }
                }
                if let Meta::List(value) = meta {
                    if value.path.is_ident("cfg_attr") {
                        let children = syn::parse2::<ConditionalAttributes>(value.tokens.clone())
                            .map_err(|error| error.to_string())?;
                        let when = all(vec![when, children.predicate]);
                        for child in &children.attributes {
                            paths(child, when.clone(), out)?;
                        }
                    }
                }
                Ok(())
            }
            let mut base = None;
            let mut overrides = Vec::new();
            for attr in &node.attrs {
                if attr.path().is_ident("path") {
                    if let Meta::NameValue(value) = &attr.meta {
                        if let Expr::Lit(lit) = &value.value {
                            if let syn::Lit::Str(path) = &lit.lit {
                                base = Some(path.value());
                                continue;
                            }
                        }
                    }
                    self.error = Some("module path must be a string literal".into());
                } else if let Err(error) = paths(&attr.meta, all(vec![]), &mut overrides) {
                    self.error = Some(error);
                }
            }
            self.external.push(json!({"modules":self.modules,"path":base,"path_overrides":overrides,"predicate":all(self.guards.clone())}));
        }
        visit::visit_item_mod(self, node);
        self.modules.pop();
    }
}
pub fn collect(file: &syn::File) -> Result<Value, String> {
    let mut collector = Collector {
        guards: attributes(&file.attrs)?,
        ..Default::default()
    };
    let file_predicate = all(collector.guards.clone());
    collector.visit_file(file);
    if let Some(error) = collector.error {
        return Err(error);
    }
    Ok(
        json!({"schema_version":1,"file_predicate":file_predicate,"regions":collector.regions,"external_modules":collector.external}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(source: &str) -> Value {
        let syntax=syn::parse_file(source);assert!(syntax.is_ok(),"original fixture must be valid Rust syntax");
        let result=collect(&syntax.unwrap());assert!(result.is_ok(),"valid cfg source must produce a complete inventory: {result:?}");
        let value = result.unwrap();
        assert!(value.is_object(), "a cfg inventory must be an object");
        assert_eq!(value["schema_version"], 1);
        assert!(value["file_predicate"].is_object(), "file predicate must be structured");
        for field in ["regions", "external_modules"] {
            assert!(value[field].is_array(), "cfg inventory {field} must be an array");
        }
        value
    }
    #[test]
    fn predicate_grammar_preserves_empty_combinators_values_and_nested_attributes() {
        let value = parse(
            "#![cfg(any(unix,windows))]\n#[cfg_attr(all(target_os=\"linux\",not(feature=\"off\")),cfg(any(target_env=\"gnu\",target_env=\"musl\")))] fn f(){}\n",
        );
        assert_eq!(value["regions"].as_array().unwrap().len(), 1);
        assert_eq!(
            value["file_predicate"]["items"][0]["items"][1]["kind"],
            "any"
        );
        assert!(value.to_string().contains("target_env"));
        for bad in [
            "#[cfg(not(unix,windows))]fn f(){}",
            "#[cfg(xor(unix))]fn f(){}",
            "#[cfg(target_os=1)]fn f(){}",
            "#[cfg_attr(unix)]fn f(){}",
        ] {
            assert!(collect(&syn::parse_file(bad).unwrap()).is_err());
        }
    }
    #[test]
    fn mixed_functions_inline_modules_and_external_paths_keep_ancestry_and_spans() {
        let value = parse(
            "#[cfg(windows)] mod win { #[cfg(target_arch=\"aarch64\")] mod native; }\nfn common(){}\n#[cfg(unix)] fn unix(){}\n#[cfg_attr(windows,path=\"win.rs\")] mod platform;\n",
        );
        assert_eq!(value["external_modules"].as_array().unwrap().len(), 2);
        assert_eq!(
            value["external_modules"][0]["modules"],
            json!(["win", "native"])
        );
        assert!(
            value["external_modules"][0]["predicate"]
                .to_string()
                .contains("windows")
        );
        assert_eq!(
            value["external_modules"][1]["path_overrides"][0]["path"],
            "win.rs"
        );
        assert!(
            value["regions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|region| region["span"]["start"]["line"] == 3)
        );
    }
    #[test]
    fn cfg_macro_branches_are_distinct_while_dynamic_operands_remain_unknown() {
        let value = parse(
            "fn f(dynamic:bool){if cfg!(windows)&&dynamic {one();} else {two();} if dynamic {three();}}\n",
        );
        assert_eq!(value["regions"].as_array().unwrap().len(), 2);
        assert!(
            value["regions"][0]["predicate"]
                .to_string()
                .contains("unknown")
        );
        assert_eq!(value["regions"][1]["predicate"]["items"][0]["kind"], "not");
    }
    #[test]
    fn boolean_predicates_raw_identifiers_and_trailing_commas_follow_rust_cfg_grammar() {
        let value = parse(
            "#[cfg(true,)]fn yes(){}\n#[cfg_attr(false,cfg(any()))]fn retained(){}\n#[cfg(r#unix)]fn unix(){}\n#[cfg(all(true,not(false),))]fn all(){}\n",
        );
        assert_eq!(value["regions"].as_array().unwrap().len(), 4);
        assert_eq!(
            value["regions"][2]["predicate"]["items"][0]["items"][1],
            json!({"kind":"flag","name":"unix"})
        );
    }
}
