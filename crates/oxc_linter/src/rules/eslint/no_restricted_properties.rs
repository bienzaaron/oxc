use oxc_ast::{
    ast::{AssignmentTargetProperty, Expression, PropertyKey},
    AstKind,
};
use oxc_diagnostics::OxcDiagnostic;
use oxc_macros::declare_oxc_lint;
use oxc_span::Span;
use oxc_str::CompactStr;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::{context::LintContext, rule::Rule, AstNode};

fn no_restricted_properties_diagnostic(
    object_name_option: Option<&CompactStr>,
    property_name_option: Option<&CompactStr>,
    message_option: Option<&CompactStr>,
    span: Span,
) -> OxcDiagnostic {
    let warn_text = match message_option {
        Some(message) => message.as_str().to_string(),
        _ => match (object_name_option, property_name_option) {
            (Some(object_name), Some(property_name)) => {
                format!("'{object_name}.{property_name}' is restricted from being used.")
            }
            (None, Some(property_name)) => {
                format!("'{property_name}' is restricted from being used.")
            }
            (Some(object_name), None) => {
                format!("'{object_name}' is restricted from being used.")
            }
            _ => "This value is restricted from being used.".to_string(),
        },
    };

    OxcDiagnostic::warn(warn_text).with_label(span)
}

#[derive(Debug, Default, Clone, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
struct PropertyDetails {
    object: Option<CompactStr>,
    property: Option<CompactStr>,
    message: Option<CompactStr>,
    allow_objects: Option<Vec<CompactStr>>,
    allow_properties: Option<Vec<CompactStr>>,
}

#[derive(Debug, Default, Clone, JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct NoRestrictedProperties {
    restricted_properties: Box<Vec<PropertyDetails>>,
}

declare_oxc_lint!(
    /// ### What it does
    ///
    /// This rule allows you to disallow access to certain properties on certain objects.
    ///
    /// ### Why is this bad?
    ///
    /// Certain properties on objects may be disallowed in a codebase. This is useful for
    /// deprecating an API or restricting usage of a module’s methods. For example, you may want
    /// to disallow using describe.only when using Mocha or telling people to use Object.assign
    /// instead of _.extend.
    ///
    /// ### Examples
    ///
    /// If we have options:
    ///
    /// ```json
    /// "no-restricted-properties": ["error", {
    ///   "object": "JSON",
    ///   "property": "parse"
    /// }]
    /// ```
    ///
    /// Examples of **incorrect** code for this rule:
    /// ```js
    /// /* no-restricted-properties: ["error", { "object": "JSON", "property": "parse" }] */
    ///
    /// JSON.parse('{ "json": "here" }') // 'JSON.parse' is restricted from being used.
    /// ```
    ///
    /// Examples of **correct** code for this rule:
    /// ```js
    /// /* no-restricted-properties: ["error", { "object": "JSON", "property": "parse" }] */
    ///
    /// JSON.stringify({ json: "here" })
    /// ```
    ///
    /// ### Options
    ///
    /// This rule takes a list of objects detailing the property to be disallowed.
    ///
    /// "no-restricted-properties": [
    ///   "error",
    ///   {
    ///      "object": "JSON",
    ///      "property": "parse"
    ///   },
    ///   {
    ///      "object": "JSON",
    ///      "property": "stringify"
    ///   }
    /// ]
    ///
    /// #### details.object
    ///
    /// The object on which the property is being accessed.
    ///
    /// #### details.property
    ///
    /// The property being accessed. If `details.object` is not specified, then the rule applies to
    /// the named property on all objects.
    ///
    /// #### details.message
    ///
    /// A custom message to display. This can be helpful if you want to guide users to using the
    /// correct API.
    ///
    /// #### details.allowObjects
    ///
    /// An allowlist of objects, where property access should be allowed. This option must be used
    /// alongside `details.property` and cannot be used alongside `details.object`.
    ///
    /// This is useful when you want to globally disable property access for a property, but allow
    /// access on certain objects.
    ///
    /// #### details.allowProperties
    ///
    /// An allowlist of properties, where property access should be allowed. This option must be
    /// used alongside `details.object` and cannot be used alongside `details.property`.
    ///
    /// This is useful when you want to globally disable property access for an object, but allow
    /// certain properties.
    ///
    NoRestrictedProperties,
    eslint,
    restriction,
    none,
    config = NoRestrictedProperties,
    version = "next",
);

fn add_configuration_properties_from_object(
    properties: &mut Vec<PropertyDetails>,
    property_details: &Map<String, Value>,
) {
    match serde_json::from_value::<PropertyDetails>(serde_json::Value::Object(
        property_details.clone(),
    )) {
        Ok(details) => properties.push(details),
        _ => (),
    }
}

impl Rule for NoRestrictedProperties {
    fn from_configuration(value: serde_json::Value) -> Result<Self, serde_json::error::Error> {
        let mut properties: Vec<PropertyDetails> = Vec::new();
        match &value {
            Value::Array(config_properties) => {
                config_properties.iter().for_each(|property_details| match property_details {
                    Value::Object(property_details) => {
                        add_configuration_properties_from_object(&mut properties, property_details)
                    }

                    _ => (),
                })
            }
            Value::Object(property_details) => {
                add_configuration_properties_from_object(&mut properties, property_details)
            }
            _ => {}
        }
        Ok(Self { restricted_properties: Box::new(properties) })
    }

    fn run<'a>(&self, node: &AstNode<'a>, ctx: &LintContext<'a>) {
        match node.kind() {
            AstKind::StaticMemberExpression(expression) => {
                let object_name = match expression.object.get_identifier_reference() {
                    Some(ident) => Some(ident.name.as_str()),
                    _ => None,
                };
                let property_name = expression.property.name.as_str();
                self.check_property_access(object_name, Some(property_name), expression.span, ctx);
            }
            AstKind::ComputedMemberExpression(expression) => {
                let object_name = match expression.object.get_identifier_reference() {
                    Some(ident) => Some(ident.name.as_str()),
                    _ => None,
                };
                let property_name = match &expression.expression {
                    Expression::StringLiteral(literal) => Some(literal.value.as_str()),
                    Expression::RegExpLiteral(literal) => literal.raw.map(|r| r.as_str()),
                    _ => None,
                };
                self.check_property_access(object_name, property_name, expression.span, ctx);
            }
            AstKind::ObjectAssignmentTarget(target) => {
                let parent_node = ctx.nodes().parent_node(target.node_id());

                let object_name = match parent_node.kind() {
                    AstKind::AssignmentExpression(expression) => match &expression.right {
                        Expression::Identifier(identifier) => Some(identifier.name.as_str()),
                        _ => None,
                    },
                    _ => None,
                };
                let properties = target.properties.iter().flat_map(|p| match p {
                    AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(ident) => {
                        Some((ident.binding.name.as_str(), ident.binding.span))
                    }
                    AssignmentTargetProperty::AssignmentTargetPropertyProperty(prop) => match &prop
                        .name
                    {
                        PropertyKey::Identifier(ident) => Some((ident.name.as_str(), ident.span)),
                        PropertyKey::StaticIdentifier(ident) => {
                            Some((ident.name.as_str(), ident.span))
                        }
                        PropertyKey::PrivateIdentifier(ident) => {
                            Some((ident.name.as_str(), ident.span))
                        }
                        PropertyKey::StringLiteral(ident) => {
                            Some((ident.value.as_str(), ident.span))
                        }
                        _ => None,
                    },
                });

                for property in properties {
                    self.check_property_access(object_name, Some(property.0), property.1, ctx);
                }
            }
            AstKind::ObjectPattern(pattern) => {
                let parent_node = ctx.nodes().parent_node(pattern.node_id());

                let object_name = match parent_node.kind() {
                    AstKind::VariableDeclarator(declarator) => match &declarator.init {
                        Some(value) => match value {
                            Expression::Identifier(identifier) => Some(identifier.name.as_str()),
                            _ => None,
                        },
                        _ => None,
                    },
                    AstKind::AssignmentExpression(expression) => match &expression.right {
                        Expression::Identifier(identifier) => Some(identifier.name.as_str()),
                        _ => None,
                    },
                    AstKind::AssignmentPattern(assignment_pattern) => {
                        match &assignment_pattern.right {
                            Expression::Identifier(identifier) => Some(identifier.name.as_str()),
                            _ => None,
                        }
                    }
                    AstKind::FormalParameter(parameter) => match &parameter.initializer {
                        Some(value) => match value.as_ref() {
                            Expression::Identifier(identifier) => Some(identifier.name.as_str()),
                            _ => None,
                        },
                        _ => None,
                    },
                    _ => None,
                };
                let properties = pattern.properties.iter().flat_map(|p| match &p.key {
                    PropertyKey::Identifier(ident) => Some((ident.name.as_str(), ident.span)),
                    PropertyKey::StaticIdentifier(ident) => Some((ident.name.as_str(), ident.span)),
                    PropertyKey::PrivateIdentifier(ident) => {
                        Some((ident.name.as_str(), ident.span))
                    }
                    PropertyKey::StringLiteral(ident) => Some((ident.value.as_str(), ident.span)),
                    _ => None,
                });

                for property in properties {
                    self.check_property_access(object_name, Some(property.0), property.1, ctx);
                }
            }
            _ => (),
        };
    }
}

impl NoRestrictedProperties {
    fn check_property_access<'a>(
        &self,
        object_name: Option<&str>,
        property_name: Option<&str>,
        span: Span,
        ctx: &LintContext<'a>,
    ) {
        for property in self.restricted_properties.iter() {
            if property.object.as_deref().is_none_or(|name| object_name == Some(name))
                && property.property.as_deref().is_none_or(|name| Some(name) == property_name)
                && !property.allow_objects.as_deref().is_some_and(|allow| {
                    object_name.is_some_and(|obj_name| {
                        allow.iter().any(|check| check.as_str() == obj_name)
                    })
                })
                && !property.allow_properties.as_deref().is_some_and(|allow| {
                    allow.iter().any(|check| Some(check.as_str()) == property_name)
                })
            {
                ctx.diagnostic(no_restricted_properties_diagnostic(
                    property.object.as_ref(),
                    property.property.as_ref(),
                    property.message.as_ref(),
                    span,
                ));
            }
        }
    }
}

#[test]
fn test() {
    use crate::tester::Tester;

    let pass = vec![
        (
            "someObject.someProperty",
            Some(
                serde_json::json!([ { "object": "someObject", "property": "disallowedProperty", }, ]),
            ),
        ),
        (
            "anotherObject.disallowedProperty",
            Some(
                serde_json::json!([ { "object": "someObject", "property": "disallowedProperty", }, ]),
            ),
        ),
        (
            "someObject.someProperty()",
            Some(
                serde_json::json!([ { "object": "someObject", "property": "disallowedProperty", }, ]),
            ),
        ),
        (
            "anotherObject.disallowedProperty()",
            Some(
                serde_json::json!([ { "object": "someObject", "property": "disallowedProperty", }, ]),
            ),
        ),
        (
            "anotherObject.disallowedProperty()",
            Some(
                serde_json::json!([ { "object": "someObject", "property": "disallowedProperty", "message": "Please use someObject.allowedProperty instead.", }, ]),
            ),
        ),
        (
            "anotherObject['disallowedProperty']()",
            Some(
                serde_json::json!([ { "object": "someObject", "property": "disallowedProperty", }, ]),
            ),
        ),
        (
            "obj.toString",
            Some(serde_json::json!([ { "object": "obj", "property": "__proto__", }, ])),
        ),
        (
            "toString.toString",
            Some(serde_json::json!([ { "object": "obj", "property": "foo", }, ])),
        ),
        ("obj.toString", Some(serde_json::json!([ { "object": "obj", "property": "foo", }, ]))),
        ("foo.bar", Some(serde_json::json!([ { "property": "baz", }, ]))),
        ("foo.bar", Some(serde_json::json!([ { "object": "baz", }, ]))),
        ("foo()", Some(serde_json::json!([ { "object": "foo", }, ]))),
        ("foo;", Some(serde_json::json!([ { "object": "foo", }, ]))),
        ("foo[/(?<zero>0)/]", Some(serde_json::json!([ { "property": "null", }, ]))), // { "ecmaVersion": 2018 },
        ("let bar = foo;", Some(serde_json::json!([{ "object": "foo", "property": "bar" }]))), // { "ecmaVersion": 6 },
        (
            "let {baz: bar} = foo;",
            Some(serde_json::json!([{ "object": "foo", "property": "bar" }])),
        ), // { "ecmaVersion": 6 },
        (
            "let {unrelated} = foo;",
            Some(serde_json::json!([{ "object": "foo", "property": "bar" }])),
        ), // { "ecmaVersion": 6 },
        (
            "let {baz: {bar: qux}} = foo;",
            Some(serde_json::json!([{ "object": "foo", "property": "bar" }])),
        ), // { "ecmaVersion": 6 },
        ("let {bar} = foo.baz;", Some(serde_json::json!([{ "object": "foo", "property": "bar" }]))), // { "ecmaVersion": 6 },
        ("let {baz: bar} = foo;", Some(serde_json::json!([{ "property": "bar" }]))), // { "ecmaVersion": 6 },
        (
            "let baz; ({baz: bar} = foo)",
            Some(serde_json::json!([{ "object": "foo", "property": "bar" }])),
        ), // { "ecmaVersion": 6 },
        ("let bar;", Some(serde_json::json!([{ "object": "foo", "property": "bar" }]))), // { "ecmaVersion": 6 },
        (
            "let bar; ([bar = 5] = foo);",
            Some(serde_json::json!([{ "object": "foo", "property": "1" }])),
        ), // { "ecmaVersion": 6 },
        (
            "function qux({baz: bar} = foo) {}",
            Some(serde_json::json!([{ "object": "foo", "property": "bar" }])),
        ), // { "ecmaVersion": 6 },
        ("let [bar, baz] = foo;", Some(serde_json::json!([{ "object": "foo", "property": "1" }]))), // { "ecmaVersion": 6 },
        ("let [, bar] = foo;", Some(serde_json::json!([{ "object": "foo", "property": "0" }]))), // { "ecmaVersion": 6 },
        ("let [, bar = 5] = foo;", Some(serde_json::json!([{ "object": "foo", "property": "1" }]))), // { "ecmaVersion": 6 },
        (
            "let bar; ([bar = 5] = foo);",
            Some(serde_json::json!([{ "object": "foo", "property": "0" }])),
        ), // { "ecmaVersion": 6 },
        (
            "function qux([bar] = foo) {}",
            Some(serde_json::json!([{ "object": "foo", "property": "0" }])),
        ), // { "ecmaVersion": 6 },
        (
            "function qux([, bar] = foo) {}",
            Some(serde_json::json!([{ "object": "foo", "property": "0" }])),
        ), // { "ecmaVersion": 6 },
        (
            "function qux([, bar] = foo) {}",
            Some(serde_json::json!([{ "object": "foo", "property": "1" }])),
        ), // { "ecmaVersion": 6 },
        (
            "class C { #foo; foo() { this.#foo; } }",
            Some(serde_json::json!([{ "property": "#foo" }])),
        ), // { "ecmaVersion": 2022 },
        (
            "someObject.disallowedProperty",
            Some(
                serde_json::json!([ { "property": "disallowedProperty", "allowObjects": ["someObject"], }, ]),
            ),
        ),
        (
            "someObject.disallowedProperty; anotherObject.disallowedProperty();",
            Some(
                serde_json::json!([ { "property": "disallowedProperty", "allowObjects": ["someObject", "anotherObject"], }, ]),
            ),
        ),
        (
            "someObject.disallowedProperty()",
            Some(
                serde_json::json!([ { "property": "disallowedProperty", "allowObjects": ["someObject"], }, ]),
            ),
        ),
        (
            "someObject['disallowedProperty']()",
            Some(
                serde_json::json!([ { "property": "disallowedProperty", "allowObjects": ["someObject"], }, ]),
            ),
        ),
        (
            "let {bar} = foo;",
            Some(serde_json::json!([{ "property": "bar", "allowObjects": ["foo"] }])),
        ), // { "ecmaVersion": 6 },
        (
            "let {baz: bar} = foo;",
            Some(serde_json::json!([{ "property": "baz", "allowObjects": ["foo"] }])),
        ), // { "ecmaVersion": 6 },
        (
            "someObject.disallowedProperty",
            Some(
                serde_json::json!([ { "object": "someObject", "allowProperties": ["disallowedProperty"], }, ]),
            ),
        ),
        (
            "someObject.disallowedProperty; someObject.anotherDisallowedProperty();",
            Some(
                serde_json::json!([ { "object": "someObject", "allowProperties": [ "disallowedProperty", "anotherDisallowedProperty", ], }, ]),
            ),
        ),
        (
            "someObject.disallowedProperty()",
            Some(
                serde_json::json!([ { "object": "someObject", "allowProperties": ["disallowedProperty"], }, ]),
            ),
        ),
        (
            "someObject['disallowedProperty']()",
            Some(
                serde_json::json!([ { "object": "someObject", "allowProperties": ["disallowedProperty"], }, ]),
            ),
        ),
        (
            "let {bar} = foo;",
            Some(serde_json::json!([ { "object": "foo", "allowProperties": ["bar"], }, ])),
        ), // { "ecmaVersion": 6 },
        (
            "let {baz: bar} = foo;",
            Some(serde_json::json!([ { "object": "foo", "allowProperties": ["baz"], }, ])),
        ), // { "ecmaVersion": 6 }
        ("(foo || bar).baz", Some(serde_json::json!([{ "object": "foo", "property": "baz" }]))),
    ];

    let fail = vec![
        (
            "someObject.disallowedProperty",
            Some(
                serde_json::json!([ { "object": "someObject", "property": "disallowedProperty", }, ]),
            ),
        ),
        (
            "someObject.disallowedProperty",
            Some(
                serde_json::json!([ { "object": "someObject", "property": "disallowedProperty", "message": "Please use someObject.allowedProperty instead.", }, ]),
            ),
        ),
        (
            "someObject.disallowedProperty; anotherObject.anotherDisallowedProperty()",
            Some(
                serde_json::json!([ { "object": "someObject", "property": "disallowedProperty", }, { "object": "anotherObject", "property": "anotherDisallowedProperty", }, ]),
            ),
        ),
        (
            "foo.__proto__",
            Some(
                serde_json::json!([ { "property": "__proto__", "message": "Please use Object.getPrototypeOf instead.", }, ]),
            ),
        ),
        (
            "foo['__proto__']",
            Some(
                serde_json::json!([ { "property": "__proto__", "message": "Please use Object.getPrototypeOf instead.", }, ]),
            ),
        ),
        ("foo.bar.baz;", Some(serde_json::json!([{ "object": "foo" }]))),
        ("foo.bar();", Some(serde_json::json!([{ "object": "foo" }]))),
        ("foo.bar.baz();", Some(serde_json::json!([{ "object": "foo" }]))),
        ("foo.bar.baz;", Some(serde_json::json!([{ "property": "bar" }]))),
        ("foo.bar();", Some(serde_json::json!([{ "property": "bar" }]))),
        ("foo.bar.baz();", Some(serde_json::json!([{ "property": "bar" }]))),
        ("foo[/(?<zero>0)/]", Some(serde_json::json!([{ "property": "/(?<zero>0)/" }]))), // { "ecmaVersion": 2018 },
        (
            "require.call({}, 'foo')",
            Some(
                serde_json::json!([ { "object": "require", "message": "Please call require() directly.", }, ]),
            ),
        ),
        ("require['resolve']", Some(serde_json::json!([ { "object": "require", }, ]))),
        ("let {bar} = foo;", Some(serde_json::json!([{ "object": "foo", "property": "bar" }]))), // { "ecmaVersion": 6 },
        (
            "let {bar: baz} = foo;",
            Some(serde_json::json!([{ "object": "foo", "property": "bar" }])),
        ), // { "ecmaVersion": 6 },
        (
            "let {'bar': baz} = foo;",
            Some(serde_json::json!([{ "object": "foo", "property": "bar" }])),
        ), // { "ecmaVersion": 6 },
        (
            "let {bar: {baz: qux}} = foo;",
            Some(serde_json::json!([{ "object": "foo", "property": "bar" }])),
        ), // { "ecmaVersion": 6 },
        ("let {bar} = foo;", Some(serde_json::json!([{ "object": "foo" }]))), // { "ecmaVersion": 6 },
        ("let {bar: baz} = foo;", Some(serde_json::json!([{ "object": "foo" }]))), // { "ecmaVersion": 6 },
        ("let {bar} = foo;", Some(serde_json::json!([{ "property": "bar" }]))), // { "ecmaVersion": 6 },
        (
            "let bar; ({bar} = foo);",
            Some(serde_json::json!([{ "object": "foo", "property": "bar" }])),
        ), // { "ecmaVersion": 6 },
        (
            "let bar; ({bar: baz = 1} = foo);",
            Some(serde_json::json!([{ "object": "foo", "property": "bar" }])),
        ), // { "ecmaVersion": 6 },
        (
            "function qux({bar} = foo) {}",
            Some(serde_json::json!([{ "object": "foo", "property": "bar" }])),
        ), // { "ecmaVersion": 6 },
        (
            "function qux({bar: baz} = foo) {}",
            Some(serde_json::json!([{ "object": "foo", "property": "bar" }])),
        ), // { "ecmaVersion": 6 },
        (
            "var {['foo']: qux, bar} = baz",
            Some(serde_json::json!([{ "object": "baz", "property": "foo" }])),
        ), // { "ecmaVersion": 6 },
        ("obj['#foo']", Some(serde_json::json!([{ "property": "#foo" }]))),
        ("const { bar: { bad } = {} } = foo;", Some(serde_json::json!([{ "property": "bad" }]))), // { "ecmaVersion": 6 },
        ("const { bar: { bad } } = foo;", Some(serde_json::json!([{ "property": "bad" }]))), // { "ecmaVersion": 6 },
        ("const { bad } = foo();", Some(serde_json::json!([{ "property": "bad" }]))), // { "ecmaVersion": 6 },
        ("({ bad } = foo());", Some(serde_json::json!([{ "property": "bad" }]))), // { "ecmaVersion": 6 },
        ("({ bar: { bad } } = foo);", Some(serde_json::json!([{ "property": "bad" }]))), // { "ecmaVersion": 6 },
        ("({ bar: { bad } = {} } = foo);", Some(serde_json::json!([{ "property": "bad" }]))), // { "ecmaVersion": 6 },
        ("({ bad }) => {};", Some(serde_json::json!([{ "property": "bad" }]))), // { "ecmaVersion": 6 },
        ("({ bad } = {}) => {};", Some(serde_json::json!([{ "property": "bad" }]))), // { "ecmaVersion": 6 },
        ("({ bad: bar }) => {};", Some(serde_json::json!([{ "property": "bad" }]))), // { "ecmaVersion": 6 },
        ("({ bar: { bad } = {} }) => {};", Some(serde_json::json!([{ "property": "bad" }]))), // { "ecmaVersion": 6 },
        ("[{ bad }] = foo;", Some(serde_json::json!([{ "property": "bad" }]))), // { "ecmaVersion": 6 },
        ("const [{ bad }] = foo;", Some(serde_json::json!([{ "property": "bad" }]))), // { "ecmaVersion": 6 },
        (
            "someObject.disallowedProperty",
            Some(
                serde_json::json!([ { "property": "disallowedProperty", "allowObjects": ["anotherObject"], }, ]),
            ),
        ),
        (
            "someObject.disallowedProperty",
            Some(
                serde_json::json!([ { "property": "disallowedProperty", "allowObjects": ["anotherObject"], "message": "Please use someObject.allowedProperty instead.", }, ]),
            ),
        ),
        (
            "someObject.disallowedProperty; anotherObject.anotherDisallowedProperty()",
            Some(
                serde_json::json!([ { "property": "disallowedProperty", "allowObjects": ["anotherObject"], }, { "property": "anotherDisallowedProperty", "allowObjects": ["someObject"], }, ]),
            ),
        ),
        (
            "someObject.disallowedProperty",
            Some(
                serde_json::json!([ { "object": "someObject", "allowProperties": ["allowedProperty"], }, ]),
            ),
        ),
        (
            "someObject.disallowedProperty",
            Some(
                serde_json::json!([ { "object": "someObject", "allowProperties": ["allowedProperty"], "message": "Please use someObject.allowedProperty instead.", }, ]),
            ),
        ),
        (
            "someObject.disallowedProperty; anotherObject.anotherDisallowedProperty()",
            Some(
                serde_json::json!([ { "object": "someObject", "allowProperties": ["anotherDisallowedProperty"], }, { "object": "anotherObject", "allowProperties": ["disallowedProperty"], }, ]),
            ),
        ),
    ];

    Tester::new(NoRestrictedProperties::NAME, NoRestrictedProperties::PLUGIN, pass, fail)
        .test_and_snapshot();
}
