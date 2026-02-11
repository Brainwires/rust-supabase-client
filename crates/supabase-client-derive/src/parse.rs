use syn::{DeriveInput, Field, Ident, LitStr, Meta, Token};

/// Parsed struct-level attributes from `#[table(...)]`.
#[derive(Debug)]
pub struct TableAttrs {
    pub name: String,
    pub schema: Option<String>,
}

/// Parsed field-level attributes.
#[derive(Debug)]
pub struct FieldAttrs {
    pub column_name: Option<String>,
    pub is_primary_key: bool,
    pub auto_generate: bool,
    pub skip: bool,
}

impl TableAttrs {
    pub fn from_derive_input(input: &DeriveInput) -> syn::Result<Self> {
        let mut name = None;
        let mut schema = None;

        for attr in &input.attrs {
            if !attr.path().is_ident("table") {
                continue;
            }
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("name") {
                    let _eq: Token![=] = meta.input.parse()?;
                    let lit: LitStr = meta.input.parse()?;
                    name = Some(lit.value());
                    Ok(())
                } else if meta.path.is_ident("schema") {
                    let _eq: Token![=] = meta.input.parse()?;
                    let lit: LitStr = meta.input.parse()?;
                    schema = Some(lit.value());
                    Ok(())
                } else {
                    Err(meta.error("expected `name` or `schema`"))
                }
            })?;
        }

        let name = name.unwrap_or_else(|| {
            // Default to snake_case of struct name
            to_snake_case(&input.ident.to_string())
        });

        Ok(Self { name, schema })
    }
}

impl FieldAttrs {
    pub fn from_field(field: &Field) -> syn::Result<Self> {
        let mut column_name = None;
        let mut is_primary_key = false;
        let mut auto_generate = false;
        let mut skip = false;

        for attr in &field.attrs {
            if attr.path().is_ident("primary_key") {
                is_primary_key = true;
                // Check for #[primary_key(auto_generate)]
                if let Meta::List(_) = &attr.meta {
                    attr.parse_nested_meta(|meta| {
                        if meta.path.is_ident("auto_generate") {
                            auto_generate = true;
                            Ok(())
                        } else {
                            Err(meta.error("expected `auto_generate`"))
                        }
                    })?;
                }
            } else if attr.path().is_ident("column") {
                attr.parse_nested_meta(|meta| {
                    if meta.path.is_ident("name") {
                        let _eq: Token![=] = meta.input.parse()?;
                        let lit: LitStr = meta.input.parse()?;
                        column_name = Some(lit.value());
                        Ok(())
                    } else if meta.path.is_ident("skip") {
                        skip = true;
                        Ok(())
                    } else if meta.path.is_ident("auto_generate") {
                        auto_generate = true;
                        Ok(())
                    } else {
                        Err(meta.error("expected `name`, `skip`, or `auto_generate`"))
                    }
                })?;
            }
        }

        Ok(Self {
            column_name,
            is_primary_key,
            auto_generate,
            skip,
        })
    }
}

/// Convert a CamelCase name to snake_case.
fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    for (i, ch) in s.chars().enumerate() {
        if ch.is_uppercase() {
            if i > 0 {
                result.push('_');
            }
            result.push(ch.to_lowercase().next().unwrap());
        } else {
            result.push(ch);
        }
    }
    result
}

/// Information about a single field after parsing.
#[derive(Debug)]
pub struct ParsedField {
    pub ident: Ident,
    pub column_name: String,
    pub is_primary_key: bool,
    pub auto_generate: bool,
    pub skip: bool,
}

/// Parse all fields from a struct.
pub fn parse_fields(fields: &syn::Fields) -> syn::Result<Vec<ParsedField>> {
    let named = match fields {
        syn::Fields::Named(named) => named,
        _ => return Err(syn::Error::new_spanned(
            proc_macro2::TokenStream::new(),
            "Table can only be derived for structs with named fields",
        )),
    };

    named
        .named
        .iter()
        .map(|field| {
            let ident = field.ident.clone().expect("named field must have ident");
            let attrs = FieldAttrs::from_field(field)?;
            let column_name = attrs
                .column_name
                .unwrap_or_else(|| ident.to_string());

            Ok(ParsedField {
                ident,
                column_name,
                is_primary_key: attrs.is_primary_key,
                auto_generate: attrs.auto_generate,
                skip: attrs.skip,
            })
        })
        .collect()
}
