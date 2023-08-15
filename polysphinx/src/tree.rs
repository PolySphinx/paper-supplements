//! Tree representation for PolySphinx.
//!
//! This module implements a representation of a multicast path, as it is used in PolySphinx. It is
//! different from a generic tree, as each node consists of two parts: the first part is the
//! "direct" path, while the second part is the inner value (which can be either a single recipient
//! or the recursive multicast information).
//!
//! The "tree" is kept generic, as it can not only be used to describe a path (using the
//! identifiers and public key of the mix nodes), but also to describe the keys that should be used
//! along the path, or any other extra information for the mix nodes.
use serde::{Deserialize, Serialize};

/// An enum to describe the path that a message should take.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tree<E, N> {
    /// Direct path along the given mix nodes.
    Direct(Vec<E>, N),
    /// Multicast path along the given mix nodes.
    Multi(Vec<E>, Vec<(E, Tree<E, N>)>),
}

impl<E, N> Tree<E, N> {
    /// Returns the level of this path.
    pub fn level(&self) -> u32 {
        match *self {
            Tree::Direct(_, _) => 0,
            Tree::Multi(_, ref inner) => {
                1 + inner.iter().map(|(_, i)| i.level()).max().unwrap_or(0)
            }
        }
    }

    /// Check whether the path is uniform, that is all inner paths have the same level.
    pub fn is_uniform(&self) -> bool {
        match *self {
            Tree::Direct(_, _) => true,
            Tree::Multi(_, ref inner) => {
                let level = self.level();
                inner.iter().all(|(_, i)| i.level() + 1 == level)
            }
        }
    }

    /// Returns the first element of the "direct" part of the path.
    ///
    /// Panics if the direct part is empty.
    pub fn first(&self) -> &E {
        match *self {
            Tree::Direct(ref edges, _) => &edges[0],
            Tree::Multi(ref edges, _) => &edges[0],
        }
    }

    /// Apply a function to all items of this tree.
    pub fn map<F, G, E1, N1>(self, mut f: F, mut g: G) -> Tree<E1, N1>
    where
        F: FnMut(E) -> E1,
        G: FnMut(N) -> N1,
    {
        self.map_inner(&mut f, &mut g)
    }

    fn map_inner<F, G, E1, N1>(self, f: &mut F, g: &mut G) -> Tree<E1, N1>
    where
        F: FnMut(E) -> E1,
        G: FnMut(N) -> N1,
    {
        match self {
            Tree::Direct(edges, node) => Tree::Direct(edges.into_iter().map(f).collect(), g(node)),
            Tree::Multi(edges, inner) => Tree::Multi(
                edges.into_iter().map(&mut *f).collect(),
                inner
                    .into_iter()
                    .map(|(n, i)| (f(n), i.map_inner(&mut *f, &mut *g)))
                    .collect(),
            ),
        }
    }
}
