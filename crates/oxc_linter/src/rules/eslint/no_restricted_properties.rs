use std::fmt::Write;

use itertools::Itertools;
use schemars::JsonSchema;
use serde::{Deserialize, de};
use serde_json::Value;

use oxc_ast::{
    AstKind,
    ast::{AssignmentTargetProperty, Expression, PropertyKey},
};
use oxc_diagnostics::OxcDiagnostic;
use oxc_macros::declare_oxc_lint;
use oxc_span::{GetSpan, Span};
use oxc_str::CompactStr;

use crate::{AstNode, context::LintContext, rule::Rule};

fn no_restricted_properties_diagnostic(property: &PropertyDetails, span: Span) -> OxcDiagnostic {
    let mut warn_text = match &property.message {
        Some(message) => message.as_str().to_string(),
        _ => match (&property.object, &property.property) {
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

    if let (Some(property_name), Some(allow_objects)) =
        (&property.property, &property.allow_objects)
    {
        write!(
            warn_text,
            " Property '{property_name}' is only allowed on these objects: {}.",
            allow_objects.iter().map(CompactStr::as_str).join(", ")
        )
        .unwrap();
    }

    if let Some(allow_properties) = &property.allow_properties {
        write!(
            warn_text,
            " Only these properties are allowed: {}.",
            allow_properties.iter().map(CompactStr::as_str).join(", ")
        )
        .unwrap();
    }

    OxcDiagnostic::warn(warn_text).with_label(span)
}

fn identifier_name<'a>(expression: &'a Expression<'a>) -> Option<&'a str> {
    match expression {
        Expression::Identifier(identifier) => Some(identifier.name.as_str()),
        _ => None,
    }
}

fn expression_property_name(expression: &Expression<'_>) -> Option<CompactStr> {
    match expression {
        Expression::StringLiteral(literal) => Some(CompactStr::from(literal.value.as_str())),
        Expression::RegExpLiteral(literal) => literal.raw.map(|r| CompactStr::from(r.as_str())),
        Expression::NumericLiteral(literal) => Some(CompactStr::from(literal.value.to_string())),
        Expression::BigIntLiteral(literal) => Some(CompactStr::from(literal.value.as_str())),
        Expression::BooleanLiteral(literal) => {
            Some(CompactStr::from(if literal.value { "true" } else { "false" }))
        }
        Expression::NullLiteral(_) => Some(CompactStr::from("null")),
        Expression::TemplateLiteral(literal) if literal.quasis.len() == 1 => {
            literal.quasis[0].value.cooked.map(|cooked| CompactStr::from(cooked.as_str()))
        }
        _ => None,
    }
}

fn property_key_name_and_span(key: &PropertyKey<'_>) -> Option<(CompactStr, Span)> {
    match key {
        PropertyKey::Identifier(ident) => Some((CompactStr::from(ident.name.as_str()), ident.span)),
        PropertyKey::StaticIdentifier(ident) => {
            Some((CompactStr::from(ident.name.as_str()), ident.span))
        }
        PropertyKey::PrivateIdentifier(ident) => {
            Some((CompactStr::from(ident.name.as_str()), ident.span))
        }
        PropertyKey::StringLiteral(literal) => {
            Some((CompactStr::from(literal.value.as_str()), literal.span))
        }
        PropertyKey::RegExpLiteral(literal) => {
            literal.raw.map(|r| (CompactStr::from(r.as_str()), literal.span))
        }
        PropertyKey::NumericLiteral(literal) => {
            Some((CompactStr::from(literal.value.to_string()), literal.span))
        }
        PropertyKey::BigIntLiteral(literal) => {
            Some((CompactStr::from(literal.value.as_str()), literal.span))
        }
        PropertyKey::BooleanLiteral(literal) => {
            Some((CompactStr::from(if literal.value { "true" } else { "false" }), literal.span))
        }
        PropertyKey::NullLiteral(literal) => Some((CompactStr::from("null"), literal.span)),
        PropertyKey::TemplateLiteral(literal) if literal.quasis.len() == 1 => literal.quasis[0]
            .value
            .cooked
            .map(|cooked| (CompactStr::from(cooked.as_str()), literal.span)),
        _ => None,
    }
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
struct PropertyDetailsList(Vec<PropertyDetails>);

impl PropertyDetails {
    fn validate(&self) -> Result<(), serde_json::Error> {
        if self.object.is_none() && self.property.is_none() {
            return Err(de::Error::custom("expected either `object` or `property`"));
        }

        if self.object.is_some() && self.allow_objects.is_some() {
            return Err(de::Error::custom("`allowObjects` cannot be used with `object`"));
        }

        if self.property.is_some() && self.allow_properties.is_some() {
            return Err(de::Error::custom("`allowProperties` cannot be used with `property`"));
        }

        Ok(())
    }
}

#[derive(Debug, Default, Clone, JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct NoRestrictedProperties {
    restricted_properties: Box<PropertyDetailsList>,
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
    /// **With options:**
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
    /// **With options:**
    ///
    /// ```json
    /// "no-restricted-properties": ["error", {
    ///   "property": "extend",
    ///   "allowObjects": ["safeUtils"]
    /// }]
    /// ```
    ///
    /// Examples of **incorrect** code for this rule:
    /// ```js
    /// /* no-restricted-properties: ["error", { "property": "extend", "allowObjects": ["safeUtils"] }] */
    ///
    /// unsafeUtils.extend(value) // 'extend' is restricted from being used. Property 'extend' is only allowed on these objects: safeUtils.
    /// ```
    ///
    /// Examples of **correct** code for this rule:
    /// ```js
    /// /* no-restricted-properties: ["error", { "property": "extend", "allowObjects": ["safeUtils"] }] */
    ///
    /// safeUtils.extend(value)
    /// ```
    ///
    /// **With options:**
    ///
    /// ```json
    /// "no-restricted-properties": ["error", {
    ///   "object": "legacyApi",
    ///   "allowProperties": ["stableMethod"]
    /// }]
    /// ```
    ///
    /// Examples of **incorrect** code for this rule:
    /// ```js
    /// /* no-restricted-properties: ["error", { "object": "legacyApi", "allowProperties": ["stableMethod"] }] */
    ///
    /// legacyApi.unstableMethod() // 'legacyApi' is restricted from being used. Only these properties are allowed: stableMethod.
    /// ```
    ///
    /// Examples of **correct** code for this rule:
    /// ```js
    /// /* no-restricted-properties: ["error", { "object": "legacyApi", "allowProperties": ["stableMethod"] }] */
    ///
    /// legacyApi.stableMethod()
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

impl Rule for NoRestrictedProperties {
    fn from_configuration(value: serde_json::Value) -> Result<Self, serde_json::error::Error> {
        let mut properties: Vec<PropertyDetails> = Vec::new();
        match value {
            Value::Array(config_properties) => {
                for property_details in config_properties {
                    let details = serde_json::from_value::<PropertyDetails>(property_details)?;
                    details.validate()?;
                    properties.push(details);
                }
            }
            Value::Object(property_details) => {
                let details =
                    serde_json::from_value::<PropertyDetails>(Value::Object(property_details))?;
                details.validate()?;
                properties.push(details);
            }
            _ => {}
        }
        Ok(Self { restricted_properties: Box::new(PropertyDetailsList(properties)) })
    }

    fn run<'a>(&self, node: &AstNode<'a>, ctx: &LintContext<'a>) {
        match node.kind() {
            AstKind::StaticMemberExpression(expression) => {
                let object_name =
                    expression.object.get_identifier_reference().map(|ident| ident.name.as_str());
                let property_name = expression.property.name.as_str();
                self.check_property_access(
                    object_name,
                    Some(property_name),
                    expression.property.span,
                    ctx,
                );
            }
            AstKind::ComputedMemberExpression(expression) => {
                let object_name =
                    expression.object.get_identifier_reference().map(|ident| ident.name.as_str());
                let property_name = expression_property_name(&expression.expression);
                self.check_property_access(
                    object_name,
                    property_name.as_deref(),
                    expression.expression.span(),
                    ctx,
                );
            }
            AstKind::ObjectAssignmentTarget(target) => {
                let parent_node = ctx.nodes().parent_node(target.node_id());

                let object_name = match parent_node.kind() {
                    AstKind::AssignmentExpression(expression) => identifier_name(&expression.right),
                    _ => None,
                };
                let properties = target.properties.iter().filter_map(|p| {
                    let (property_name, span) = match p {
                        AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(ident) => {
                            (CompactStr::from(ident.binding.name.as_str()), ident.binding.span)
                        }
                        AssignmentTargetProperty::AssignmentTargetPropertyProperty(prop) => {
                            property_key_name_and_span(&prop.name)?
                        }
                    };

                    Some((property_name, span))
                });

                for (property_name, span) in properties {
                    self.check_property_access(
                        object_name,
                        Some(property_name.as_str()),
                        span,
                        ctx,
                    );
                }
            }
            AstKind::ObjectPattern(pattern) => {
                let parent_node = ctx.nodes().parent_node(pattern.node_id());

                let object_name = match parent_node.kind() {
                    AstKind::VariableDeclarator(declarator) => {
                        declarator.init.as_ref().and_then(identifier_name)
                    }
                    AstKind::AssignmentExpression(expression) => identifier_name(&expression.right),
                    AstKind::AssignmentPattern(assignment_pattern) => {
                        identifier_name(&assignment_pattern.right)
                    }
                    AstKind::FormalParameter(parameter) => {
                        parameter.initializer.as_deref().and_then(identifier_name)
                    }
                    _ => None,
                };
                let properties = pattern.properties.iter().filter_map(|p| {
                    let (property_name, span) = property_key_name_and_span(&p.key)?;

                    Some((property_name, span))
                });

                for (property_name, span) in properties {
                    self.check_property_access(
                        object_name,
                        Some(property_name.as_str()),
                        span,
                        ctx,
                    );
                }
            }
            _ => (),
        }
    }
}

impl NoRestrictedProperties {
    fn check_property_access(
        &self,
        object_name: Option<&str>,
        property_name: Option<&str>,
        span: Span,
        ctx: &LintContext<'_>,
    ) {
        for property in &self.restricted_properties.0 {
            let object_matches =
                property.object.as_deref().is_none_or(|name| object_name == Some(name));
            let property_matches =
                property.property.as_deref().is_none_or(|name| Some(name) == property_name);
            let object_allowed = property.allow_objects.as_deref().is_some_and(|allow| {
                object_name
                    .is_some_and(|obj_name| allow.iter().any(|check| check.as_str() == obj_name))
            });
            let property_allowed = property.allow_properties.as_deref().is_some_and(|allow| {
                allow.iter().any(|check| Some(check.as_str()) == property_name)
            });

            if object_matches && property_matches && !object_allowed && !property_allowed {
                ctx.diagnostic(no_restricted_properties_diagnostic(property, span));
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
        ("obj[0]", Some(serde_json::json!([{ "property": "0" }]))),
        ("obj[1n]", Some(serde_json::json!([{ "property": "1" }]))),
        ("obj[true]", Some(serde_json::json!([{ "property": "true" }]))),
        ("obj[null]", Some(serde_json::json!([{ "property": "null" }]))),
        ("obj[`foo`]", Some(serde_json::json!([{ "property": "foo" }]))),
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
        (
            "const { [100]: x } = obj;",
            Some(serde_json::json!([{ "object": "obj", "property": "100" }])),
        ), // { "ecmaVersion": 6 },
        (
            "const { [`foo`]: x } = obj;",
            Some(serde_json::json!([{ "object": "obj", "property": "foo" }])),
        ), // { "ecmaVersion": 6 },
        (
            "({ [100]: x } = obj);",
            Some(serde_json::json!([{ "object": "obj", "property": "100" }])),
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

#[test]
fn invalid_configs_error_in_from_configuration() {
    assert!(NoRestrictedProperties::from_configuration(serde_json::json!([{}])).is_err());
    assert!(
        NoRestrictedProperties::from_configuration(
            serde_json::json!([{ "object": "foo", "allowObjects": ["bar"] }])
        )
        .is_err()
    );
    assert!(
        NoRestrictedProperties::from_configuration(
            serde_json::json!([{ "property": "foo", "allowProperties": ["bar"] }])
        )
        .is_err()
    );
}
