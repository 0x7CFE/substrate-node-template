//! The Substrate runtime reexported for WebAssembly compile.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate template_node_runtime;
pub use template_node_runtime::*;