/*
 * ark/v1/service.proto
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: version not set
 *
 * Generated by: https://openapi-generator.tech
 */

use crate::models;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct V1SignedVtxoOutpoint {
    #[serde(rename = "outpoint", skip_serializing_if = "Option::is_none")]
    pub outpoint: Option<Box<models::V1Outpoint>>,
    #[serde(rename = "proof", skip_serializing_if = "Option::is_none")]
    pub proof: Option<Box<models::V1OwnershipProof>>,
}

impl V1SignedVtxoOutpoint {
    pub fn new() -> V1SignedVtxoOutpoint {
        V1SignedVtxoOutpoint {
            outpoint: None,
            proof: None,
        }
    }
}
