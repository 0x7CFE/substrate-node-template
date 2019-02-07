//! The Substrate Node Template runtime. This can be compiled with `#[no_std]`, ready for Wasm.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(alloc))]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit to 256.
#![recursion_limit="256"]

extern crate sr_std as rstd;
extern crate sr_io as runtime_io;
#[macro_use]
extern crate substrate_client as client;
#[macro_use]
extern crate srml_support;
#[macro_use]
extern crate sr_primitives as runtime_primitives;
#[cfg(feature = "std")]
#[macro_use]
extern crate serde_derive;
extern crate substrate_primitives as primitives;
extern crate parity_codec;
#[macro_use]
extern crate parity_codec_derive;
#[macro_use]
extern crate sr_version as version;
extern crate srml_system as system;
extern crate srml_executive as executive;
extern crate srml_consensus as consensus;
extern crate srml_timestamp as timestamp;
extern crate srml_balances as balances;
extern crate srml_sudo as sudo;
extern crate srml_aura as aura;
extern crate srml_indices as indices;
extern crate substrate_consensus_aura_primitives as consensus_aura;

use rstd::prelude::*;
#[cfg(feature = "std")]
use primitives::bytes;
use primitives::{Ed25519AuthorityId, OpaqueMetadata};
use runtime_primitives::{
	ApplyResult, transaction_validity::TransactionValidity, Ed25519Signature, generic,
	traits::{self, BlakeTwo256, Block as BlockT, StaticLookup},
};
use client::{
	block_builder::api::{CheckInherentsResult, InherentData, self as block_builder_api},
	runtime_api
};
use version::RuntimeVersion;
#[cfg(feature = "std")]
use version::NativeVersion;

// A few exports that help ease life for downstream crates.
#[cfg(any(feature = "std", test))]
pub use runtime_primitives::BuildStorage;
pub use consensus::Call as ConsensusCall;
pub use timestamp::Call as TimestampCall;
pub use runtime_primitives::{Permill, Perbill};
pub use timestamp::BlockPeriod;
pub use srml_support::StorageValue;

/// Alias to Ed25519 pubkey that identifies an account on the chain.
pub type AccountId = primitives::H256;

/// A hash of some data used by the chain.
pub type Hash = primitives::H256;

/// Index of a block number in the chain.
pub type BlockNumber = u64;

/// Index of an account's extrinsic in the chain.
pub type Nonce = u64;

pub mod utxo;

/// Opaque types. These are used by the CLI to instantiate machinery that don't need to know
/// the specifics of the runtime. They can then be made to be agnostic over specific formats
/// of data like extrinsics, allowing for them to continue syncing the network through upgrades
/// to even the core datastructures.
pub mod opaque {
	use super::*;

	/// Opaque, encoded, unchecked extrinsic.
	#[derive(PartialEq, Eq, Clone, Default, Encode, Decode)]
	#[cfg_attr(feature = "std", derive(Serialize, Deserialize, Debug))]
	pub struct UncheckedExtrinsic(#[cfg_attr(feature = "std", serde(with="bytes"))] pub Vec<u8>);
	impl traits::Extrinsic for UncheckedExtrinsic {
		fn is_signed(&self) -> Option<bool> {
			None
		}
	}
	/// Opaque block header type.
	pub type Header = generic::Header<BlockNumber, BlakeTwo256, generic::DigestItem<Hash, Ed25519AuthorityId>>;
	/// Opaque block type.
	pub type Block = generic::Block<Header, UncheckedExtrinsic>;
	/// Opaque block identifier type.
	pub type BlockId = generic::BlockId<Block>;
	/// Opaque session key type.
	pub type SessionKey = Ed25519AuthorityId;
}

/// This runtime version.
pub const VERSION: RuntimeVersion = RuntimeVersion {
	spec_name: create_runtime_str!("utxo-node"),
	impl_name: create_runtime_str!("utxo-node"),
	authoring_version: 3,
	spec_version: 3,
	impl_version: 0,
	apis: RUNTIME_API_VERSIONS,
};

/// The version infromation used to identify this runtime when compiled natively.
#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
	NativeVersion {
		runtime_version: VERSION,
		can_author_with: Default::default(),
	}
}

impl system::Trait for Runtime {
	/// The identifier used to distinguish between accounts.
	type AccountId = AccountId;
	/// The lookup mechanism to get account ID from whatever is passed in dispatchers.
	type Lookup = Indices;
	/// The index type for storing how many extrinsics an account has signed.
	type Index = Nonce;
	/// The index type for blocks.
	type BlockNumber = BlockNumber;
	/// The type for hashing blocks and tries.
	type Hash = Hash;
	/// The hashing algorithm used.
	type Hashing = BlakeTwo256;
	/// The header digest type.
	type Digest = generic::Digest<Log>;
	/// The header type.
	type Header = generic::Header<BlockNumber, BlakeTwo256, Log>;
	/// The ubiquitous event type.
	type Event = Event;
	/// The ubiquitous log type.
	type Log = Log;
	/// The ubiquitous origin type.
	type Origin = Origin;
}

impl aura::Trait for Runtime {
	type HandleReport = ();
}

impl consensus::Trait for Runtime {
	/// The identifier we use to refer to authorities.
	type SessionKey = Ed25519AuthorityId;
	// The aura module handles offline-reports internally
	// rather than using an explicit report system.
	type InherentOfflineReport = ();
	/// The ubiquitous log type.
	type Log = Log;
}

impl indices::Trait for Runtime {
	/// The type for recording indexing into the account enumeration. If this ever overflows, there
	/// will be problems!
	type AccountIndex = u32;
	/// Use the standard means of resolving an index hint from an id.
	type ResolveHint = indices::SimpleResolveHint<Self::AccountId, Self::AccountIndex>;
	/// Determine whether an account is dead.
	type IsDeadAccount = ();
	/// The uniquitous event type.
	type Event = Event;
}

impl timestamp::Trait for Runtime {
	/// A timestamp: seconds since the unix epoch.
	type Moment = u64;
	type OnTimestampSet = Aura;
}

impl utxo::Trait for Runtime {
	/// The uniquitous event type.
	type Event = Event;
}

impl sudo::Trait for Runtime {
	/// The uniquitous event type.
	type Event = Event;
	type Proposal = Call;
}

construct_runtime!(
	pub enum Runtime with Log(InternalLog: DigestItem<Hash, Ed25519AuthorityId>) where
		Block = Block,
		NodeBlock = opaque::Block,
		UncheckedExtrinsic = UncheckedExtrinsic
	{
		System: system::{default, Log(ChangesTrieRoot)},
		Timestamp: timestamp::{Module, Call, Storage, Config<T>, Inherent},
		Consensus: consensus::{Module, Call, Storage, Config<T>, Log(AuthoritiesChange), Inherent},
		Aura: aura::{Module},
		Indices: indices,
		Sudo: sudo,
		Utxo: utxo::{Module, Call, Storage, Config<T>, Event},
	}
);

pub struct ChainContext<T>(::rstd::marker::PhantomData<T>);

impl<T> Default for ChainContext<T> {
	fn default() -> Self {
		ChainContext(::rstd::marker::PhantomData)
	}
}

impl<T: system::Trait> runtime_primitives::traits::Lookup for ChainContext<T> {
	type Source = DummyAccountId;
	type Target = AccountId;
	fn lookup(&self, a: Self::Source) -> rstd::result::Result<Self::Target, &'static str> {
		// Ok(a)
		// unimplemented!()
		Err("unimplemented")
	}
}

impl<T: system::Trait> runtime_primitives::traits::CurrentHeight for ChainContext<T> {
	type BlockNumber = T::BlockNumber;
	fn current_height(&self) -> Self::BlockNumber {
		<system::Module<T>>::block_number()
	}
}

impl<T: system::Trait> runtime_primitives::traits::BlockNumberToHash for ChainContext<T> {
	type BlockNumber = T::BlockNumber;
	type Hash = T::Hash;
	fn block_number_to_hash(&self, n: Self::BlockNumber) -> Option<Self::Hash> {
		Some(<system::Module<T>>::block_hash(n))
	}
}

// #[cfg_attr(feature = "std", derive(Serialize, Deserialize, Debug, Hash))]
// #[derive(Ord, PartialOrd, PartialEq, Eq, Clone, Default, Encode, Decode)]
// pub struct DummySignature;

// impl runtime_primitives::traits::Verify for DummySignature {
// 	/// Type of the signer.
// 	type Signer = AccountId;

// 	/// Verify a signature. Return `true` if signature is valid for the value.
// 	fn verify<L: runtime_primitives::traits::Lazy<[u8]>>(
// 		&self,
// 		_msg: L,
// 		_signer: &Self::Signer,
// 	) -> bool {
// 		false
// 	}
// }

/// Alias to Ed25519 pubkey that identifies an account on the chain.
#[cfg_attr(feature = "std", derive(Serialize, Deserialize, Debug, Hash))]
#[derive(Ord, PartialOrd, PartialEq, Eq, Clone, Default, Encode, Decode)]
pub struct DummyAccountId;

#[cfg(feature = "std")]
impl std::fmt::Display for DummyAccountId {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> rstd::fmt::Result {
		write!(f, "DummyAccountId")
	}
}

/// The type used as a helper for interpreting the sender of transactions.
type Context = ChainContext<Runtime>; // system::ChainContext<Runtime>;
/// The address format for describing accounts.
type Address = DummyAccountId; // <Indices as StaticLookup>::Source;
/// Block header type as expected by this runtime.
pub type Header = generic::Header<BlockNumber, BlakeTwo256, Log>;
/// Block type as expected by this runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;
/// BlockId type as expected by this runtime.
pub type BlockId = generic::BlockId<Block>;
/// Unchecked extrinsic type as expected by this runtime.
pub type UncheckedExtrinsic = generic::UncheckedMortalCompactExtrinsic<Address, Nonce, Call, Ed25519Signature>;
/// Extrinsic type that has already been checked.
pub type CheckedExtrinsic = generic::CheckedExtrinsic<AccountId, Nonce, Call>;
/// Executive: handles dispatch to the various modules.
pub type Executive = executive::Executive<Runtime, Block, Context, (), AllModules>;

// Implement our runtime API endpoints. This is just a bunch of proxying.
impl_runtime_apis! {
	impl runtime_api::Core<Block> for Runtime {
		fn version() -> RuntimeVersion {
			VERSION
		}

		fn authorities() -> Vec<Ed25519AuthorityId> {
			Consensus::authorities()
		}

		fn execute_block(block: Block) {
			Executive::execute_block(block)
		}

		fn initialise_block(header: &<Block as BlockT>::Header) {
			Executive::initialise_block(header)
		}
	}

	impl runtime_api::Metadata<Block> for Runtime {
		fn metadata() -> OpaqueMetadata {
			Runtime::metadata().into()
		}
	}

	impl block_builder_api::BlockBuilder<Block> for Runtime {
		fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> ApplyResult {
			Executive::apply_extrinsic(extrinsic)
		}

		fn finalise_block() -> <Block as BlockT>::Header {
			Executive::finalise_block()
		}

		fn inherent_extrinsics(data: InherentData) -> Vec<<Block as BlockT>::Extrinsic> {
			data.create_extrinsics()
		}

		fn check_inherents(block: Block, data: InherentData) -> CheckInherentsResult {
			data.check_extrinsics(&block)
		}

		fn random_seed() -> <Block as BlockT>::Hash {
			System::random_seed()
		}
	}

	impl runtime_api::TaggedTransactionQueue<Block> for Runtime {
		fn validate_transaction(tx: <Block as BlockT>::Extrinsic) -> TransactionValidity {
			use srml_support::IsSubType;
			use runtime_primitives::{
				traits::Hash,
				transaction_validity::{TransactionLongevity, TransactionPriority, TransactionValidity},
			};

			// Extrinsics representing UTXO transaction need some special handling
			if let Some(&utxo::Call::execute(ref transaction)) = IsSubType::<utxo::Module<Runtime>>::is_aux_sub_type(&tx.function) {
				// List of tags to require
				let requires;

				// Transaction priority to assign
				let priority;

				match <utxo::Module<Runtime>>::check_transaction(&transaction) {
					// Verification failed
					Err(e) => {
						runtime_io::print(e);
						return TransactionValidity::Invalid;
					}

					// Transaction was fully verified and is valid
					Ok(utxo::CheckInfo::Totals { input, output }) => {
						// All input UTXOs were found, so we consider input conditions to be met
						requires = Vec::new();

						// Priority is based on a transaction fee that is equal to the leftover value
						let max_priority = utxo::Value::from(TransactionPriority::max_value());
						priority = max_priority.min(input - output) as TransactionPriority;
					}

					// All checks passed except that some of inputs are missing
					Ok(utxo::CheckInfo::MissingInputs(missing)) => {
						// Since some referred UTXOs were not found in the storage yet,
						// we tag current transaction as requiring those particular UTXOs
						requires = missing
							.iter()
							.map(|hash| hash.as_fixed_bytes().to_vec())
							.collect();

						// Transaction could not be validated at this point,
						// so we have no sane way to calculate the priority
						priority = 0;
					}
				}

				// Output tags that this transaction provides
				let provides = transaction.outputs
					.iter()
					.map(|output| BlakeTwo256::hash_of(output).as_fixed_bytes().to_vec())
					.collect();

				return TransactionValidity::Valid {
					requires,
					provides,
					priority,
					longevity: TransactionLongevity::max_value(),
				};
			}

			// Fall back to default logic for other extrinsics
			Executive::validate_transaction(tx)
		}
	}

	impl consensus_aura::AuraApi<Block> for Runtime {
		fn slot_duration() -> u64 {
			Aura::slot_duration()
		}
	}
}
