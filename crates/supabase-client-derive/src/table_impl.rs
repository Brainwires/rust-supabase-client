use proc_macro2::TokenStream;
use quote::quote;
use syn::DeriveInput;

use crate::parse::{parse_fields, ParsedField, TableAttrs};

/// Path to the `supabase-client-query` crate as seen from the crate using
/// the derive: the query crate itself when it is a direct dependency
/// (possibly renamed), otherwise `supabase_client_sdk::__query`.
fn query_crate() -> TokenStream {
    use proc_macro_crate::{FoundCrate, crate_name};
    let ident = |name: &str| proc_macro2::Ident::new(name, proc_macro2::Span::call_site());
    match crate_name("supabase-client-query") {
        Ok(FoundCrate::Itself) => quote!(crate),
        Ok(FoundCrate::Name(name)) => {
            let name = ident(&name);
            quote!(::#name)
        }
        Err(_) => match crate_name("supabase-client-sdk") {
            Ok(FoundCrate::Itself) => quote!(crate::__query),
            Ok(FoundCrate::Name(name)) => {
                let name = ident(&name);
                quote!(::#name::__query)
            }
            Err(_) => quote!(::supabase_client_query),
        },
    }
}

pub fn expand_table_derive(input: &DeriveInput) -> syn::Result<TokenStream> {
    let struct_name = &input.ident;
    let q = query_crate();
    let table_attrs = TableAttrs::from_derive_input(input)?;

    let data_struct = match &input.data {
        syn::Data::Struct(s) => s,
        _ => {
            return Err(syn::Error::new_spanned(
                struct_name,
                "Table can only be derived for structs",
            ))
        }
    };
    let fields = parse_fields(&data_struct.fields)?;

    let table_name = &table_attrs.name;
    let schema_name = table_attrs.schema.as_deref().unwrap_or("public");

    // Collect the different field categories
    let all_fields: Vec<&ParsedField> = fields.iter().filter(|f| !f.skip).collect();
    let pk_fields: Vec<&ParsedField> = all_fields
        .iter()
        .filter(|f| f.is_primary_key)
        .copied()
        .collect();
    let insertable_fields: Vec<&ParsedField> = all_fields
        .iter()
        .filter(|f| !f.auto_generate)
        .copied()
        .collect();
    let non_pk_fields: Vec<&ParsedField> = all_fields
        .iter()
        .filter(|f| !f.is_primary_key)
        .copied()
        .collect();

    // Generate static arrays for column names
    let all_column_names: Vec<&str> = all_fields.iter().map(|f| f.column_name.as_str()).collect();
    let pk_column_names: Vec<&str> = pk_fields.iter().map(|f| f.column_name.as_str()).collect();
    let insertable_column_names: Vec<&str> = insertable_fields
        .iter()
        .map(|f| f.column_name.as_str())
        .collect();

    // Generate field_to_column match arms
    let field_to_column_arms: Vec<TokenStream> = all_fields
        .iter()
        .map(|f| {
            let field_name = f.ident.to_string();
            let col_name = &f.column_name;
            quote! { #field_name => ::core::option::Option::Some(#col_name) }
        })
        .collect();

    // Generate column_to_field match arms
    let column_to_field_arms: Vec<TokenStream> = all_fields
        .iter()
        .map(|f| {
            let field_name = f.ident.to_string();
            let col_name = &f.column_name;
            quote! { #col_name => ::core::option::Option::Some(#field_name) }
        })
        .collect();

    // Generate bind_insert: collect SqlParam for each insertable field
    let bind_insert_exprs: Vec<TokenStream> = insertable_fields
        .iter()
        .map(|f| {
            let ident = &f.ident;
            quote! {
                #q::IntoSqlParam::into_sql_param(self.#ident.clone())
            }
        })
        .collect();

    // Generate bind_update: collect SqlParam for each non-PK field
    let bind_update_exprs: Vec<TokenStream> = non_pk_fields
        .iter()
        .map(|f| {
            let ident = &f.ident;
            quote! {
                #q::IntoSqlParam::into_sql_param(self.#ident.clone())
            }
        })
        .collect();

    // Generate bind_primary_key: collect SqlParam for each PK field
    let bind_pk_exprs: Vec<TokenStream> = pk_fields
        .iter()
        .map(|f| {
            let ident = &f.ident;
            quote! {
                #q::IntoSqlParam::into_sql_param(self.#ident.clone())
            }
        })
        .collect();

    let all_count = all_column_names.len();
    let pk_count = pk_column_names.len();
    let insertable_count = insertable_column_names.len();

    Ok(quote! {
        impl #q::Table for #struct_name {
            fn table_name() -> &'static str {
                #table_name
            }

            fn schema_name() -> &'static str {
                #schema_name
            }

            fn primary_key_columns() -> &'static [&'static str] {
                static COLUMNS: [&str; #pk_count] = [#(#pk_column_names),*];
                &COLUMNS
            }

            fn column_names() -> &'static [&'static str] {
                static COLUMNS: [&str; #all_count] = [#(#all_column_names),*];
                &COLUMNS
            }

            fn insertable_columns() -> &'static [&'static str] {
                static COLUMNS: [&str; #insertable_count] = [#(#insertable_column_names),*];
                &COLUMNS
            }

            fn field_to_column(field: &str) -> ::core::option::Option<&'static str> {
                match field {
                    #(#field_to_column_arms,)*
                    _ => ::core::option::Option::None,
                }
            }

            fn column_to_field(column: &str) -> ::core::option::Option<&'static str> {
                match column {
                    #(#column_to_field_arms,)*
                    _ => ::core::option::Option::None,
                }
            }

            fn bind_insert(&self) -> ::std::vec::Vec<#q::SqlParam> {
                ::std::vec![#(#bind_insert_exprs),*]
            }

            fn bind_update(&self) -> ::std::vec::Vec<#q::SqlParam> {
                ::std::vec![#(#bind_update_exprs),*]
            }

            fn bind_primary_key(&self) -> ::std::vec::Vec<#q::SqlParam> {
                ::std::vec![#(#bind_pk_exprs),*]
            }
        }
    })
}
