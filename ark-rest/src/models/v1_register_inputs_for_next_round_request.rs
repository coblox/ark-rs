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
pub struct V1RegisterInputsForNextRoundRequest {
    #[serde(rename = "inputs", skip_serializing_if = "Option::is_none")]
    pub inputs: Option<Vec<models::V1Input>>,
    #[serde(rename = "ephemeralPubkey", skip_serializing_if = "Option::is_none")]
    pub ephemeral_pubkey: Option<String>,
    #[serde(rename = "notes", skip_serializing_if = "Option::is_none")]
    pub notes: Option<Vec<String>>,
}

impl V1RegisterInputsForNextRoundRequest {
    pub fn new() -> V1RegisterInputsForNextRoundRequest {
        V1RegisterInputsForNextRoundRequest {
            inputs: None,
            ephemeral_pubkey: None,
            notes: None,
        }
    }
}
