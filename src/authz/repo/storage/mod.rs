//! Focused authorization repositories. Domain rules and transaction ownership
//! stay in the parent; these contracts select native backend storage.
pub(super) mod actions;
pub(super) mod assignments;
pub(super) mod blocks;
pub(super) mod objects;
pub(super) mod roles;
pub(super) mod visibility;
