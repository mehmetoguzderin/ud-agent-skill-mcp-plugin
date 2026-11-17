# Local dependency examples

These examples describe the graph, without identifying the highlighted arc in the supplied image.

The nominal subject (`nsubj`) is the nominal argument functioning as the subject.
The object (`obj`) is the core nominal object of the verb.
The root (`root`) attaches the sentence's predicate to the artificial root.

```conllu
# sent_id = diagram-1
# text = Cats chased mice
1	Cats	cat	NOUN	_	_	2	nsubj	_	_
2	chased	chase	VERB	_	_	0	root	_	_
3	mice	mouse	NOUN	_	_	2	obj	_	_

```

