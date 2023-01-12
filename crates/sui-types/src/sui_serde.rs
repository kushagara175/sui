// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::marker::PhantomData;

use anyhow::anyhow;
use fastcrypto::encoding::{Base64, Encoding, Hex};
use fastcrypto::traits::ToFromBytes;
use move_core_types::account_address::AccountAddress;
use serde;
use serde::de::{Deserializer, Error};
use serde::ser::{Error as SerError, Serializer};
use serde::Deserialize;
use serde::Serialize;
use serde_with::{Bytes, DeserializeAs, SerializeAs};

use crate::crypto::{AggregateAuthoritySignature, AuthoritySignature, KeypairTraits};

#[inline]
fn to_custom_error<'de, D, E>(e: E) -> D::Error
where
    E: Debug,
    D: Deserializer<'de>,
{
    Error::custom(format!("byte deserialization failed, cause by: {:?}", e))
}

#[inline]
fn to_custom_ser_error<S, E>(e: E) -> S::Error
where
    E: Debug,
    S: Serializer,
{
    S::Error::custom(format!("byte serialization failed, cause by: {:?}", e))
}

/// Use with serde_as to control serde for human-readable serialization and deserialization
/// `H` : serde_as SerializeAs/DeserializeAs delegation for human readable in/output
/// `R` : serde_as SerializeAs/DeserializeAs delegation for non-human readable in/output
///
/// # Example:
///
/// ```text
/// #[serde_as]
/// #[derive(Deserialize, Serialize)]
/// struct Example(#[serde_as(as = "Readable<DisplayFromStr, _>")] [u8; 20]);
/// ```
///
/// The above example will delegate human-readable serde to `DisplayFromStr`
/// and array tuple (default) for non-human-readable serializer.
pub struct Readable<H, R> {
    human_readable: PhantomData<H>,
    non_human_readable: PhantomData<R>,
}

impl<T: ?Sized, H, R> SerializeAs<T> for Readable<H, R>
where
    H: SerializeAs<T>,
    R: SerializeAs<T>,
{
    fn serialize_as<S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            H::serialize_as(value, serializer)
        } else {
            R::serialize_as(value, serializer)
        }
    }
}

impl<'de, R, H, T> DeserializeAs<'de, T> for Readable<H, R>
where
    H: DeserializeAs<'de, T>,
    R: DeserializeAs<'de, T>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            H::deserialize_as(deserializer)
        } else {
            R::deserialize_as(deserializer)
        }
    }
}

/// custom serde for AccountAddress
pub struct HexObjectId;

impl SerializeAs<AccountAddress> for HexObjectId {
    fn serialize_as<S>(value: &AccountAddress, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Hex::serialize_as(value, serializer)
    }
}

impl<'de> DeserializeAs<'de, AccountAddress> for HexObjectId {
    fn deserialize_as<D>(deserializer: D) -> Result<AccountAddress, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.starts_with("0x") {
            AccountAddress::from_hex_literal(&s)
        } else {
            AccountAddress::from_hex(&s)
        }
        .map_err(to_custom_error::<'de, D, _>)
    }
}

/// DeserializeAs adaptor for `Vec<u8>` <> `TryFrom<Vec<u8>>`
pub struct TryFromVec<V> {
    vec: PhantomData<V>,
}

impl<T: ?Sized, V> SerializeAs<T> for TryFromVec<V>
where
    V: SerializeAs<T>,
{
    fn serialize_as<S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        V::serialize_as(value, serializer)
    }
}

impl<'de, V, T> DeserializeAs<'de, T> for TryFromVec<V>
where
    V: DeserializeAs<'de, Vec<u8>>,
    T: TryFrom<Vec<u8>>,
    <T as TryFrom<Vec<u8>>>::Error: std::fmt::Display,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::try_from(V::deserialize_as(deserializer)?).map_err(Error::custom)
    }
}

/// DeserializeAs adaptor for `Vec<u8>` <> `[u8;N]`
pub struct ToArray<V> {
    vec: PhantomData<V>,
}

impl<T: ?Sized, V> SerializeAs<T> for ToArray<V>
where
    V: SerializeAs<T>,
{
    fn serialize_as<S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        V::serialize_as(value, serializer)
    }
}

impl<'de, V, const N: usize> DeserializeAs<'de, [u8; N]> for ToArray<V>
where
    V: DeserializeAs<'de, Vec<u8>>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = V::deserialize_as(deserializer)?;
        if value.len() != N {
            return Err(Error::custom(anyhow!(
                "invalid array length {}, expecting {}",
                value.len(),
                N
            )));
        }
        let mut array = [0u8; N];
        array.copy_from_slice(&value[..N]);
        Ok(array)
    }
}

/// Serializes a bitmap according to the roaring bitmap on-disk standard.
/// <https://github.com/RoaringBitmap/RoaringFormatSpec>
pub struct SuiBitmap;

impl SerializeAs<roaring::RoaringBitmap> for SuiBitmap {
    fn serialize_as<S>(source: &roaring::RoaringBitmap, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = vec![];

        source
            .serialize_into(&mut bytes)
            .map_err(to_custom_ser_error::<S, _>)?;
        Bytes::serialize_as(&bytes, serializer)
    }
}

impl<'de> DeserializeAs<'de, roaring::RoaringBitmap> for SuiBitmap {
    fn deserialize_as<D>(deserializer: D) -> Result<roaring::RoaringBitmap, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Bytes::deserialize_as(deserializer)?;
        roaring::RoaringBitmap::deserialize_from(&bytes[..]).map_err(to_custom_error::<'de, D, _>)
    }
}
pub struct KeyPairBase64 {}

impl<T> SerializeAs<T> for KeyPairBase64
where
    T: KeypairTraits,
{
    fn serialize_as<S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.encode_base64().serialize(serializer)
    }
}

impl<'de, T> DeserializeAs<'de, T> for KeyPairBase64
where
    T: KeypairTraits,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        T::decode_base64(&s).map_err(to_custom_error::<'de, D, _>)
    }
}

pub struct AuthSignature {}

impl SerializeAs<AuthoritySignature> for AuthSignature {
    fn serialize_as<S>(value: &AuthoritySignature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Base64::encode(value.as_ref()).serialize(serializer)
    }
}

impl<'de> DeserializeAs<'de, AuthoritySignature> for AuthSignature {
    fn deserialize_as<D>(deserializer: D) -> Result<AuthoritySignature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let sig_bytes = Base64::decode(&s).map_err(to_custom_error::<'de, D, _>)?;
        AuthoritySignature::from_bytes(&sig_bytes[..]).map_err(to_custom_error::<'de, D, _>)
    }
}

pub struct AggrAuthSignature {}

impl SerializeAs<AggregateAuthoritySignature> for AggrAuthSignature {
    fn serialize_as<S>(
        value: &AggregateAuthoritySignature,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Base64::encode(value.as_ref()).serialize(serializer)
    }
}

impl<'de> DeserializeAs<'de, AggregateAuthoritySignature> for AggrAuthSignature {
    fn deserialize_as<D>(deserializer: D) -> Result<AggregateAuthoritySignature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let sig_bytes = Base64::decode(&s).map_err(to_custom_error::<'de, D, _>)?;
        AggregateAuthoritySignature::from_bytes(&sig_bytes[..])
            .map_err(to_custom_error::<'de, D, _>)
    }
}
