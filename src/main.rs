use ark_ff::Field;
use ark_groth16::{
    generate_random_parameters, create_random_proof, prepare_verifying_key, verify_proof,
};
use ark_bn254::{Bn254, Fr};
use ark_std::{test_rng, UniformRand};
use chrono::{DateTime, Duration, Utc};
use sha2::{Sha256, Digest};

// 行動データの構造体
#[derive(Debug)]
pub struct ActivityData {
    timestamp: DateTime<Utc>,
    activity_hash: [u8; 32],
    user_commitment: [u8; 32],
}

// 証明用の回路構造体
#[derive(Clone)]
pub struct ActivityCircuit {
    // 公開入力
    pub timestamp: u64,
    pub activity_hash: Fr,
    
    // 秘密入力
    pub user_commitment: Fr,
}

impl ActivityCircuit {
    pub fn new(
        timestamp: DateTime<Utc>,
        activity_hash: [u8; 32],
        user_commitment: [u8; 32],
    ) -> Self {
        // タイムスタンプをu64に変換
        let timestamp_u64 = timestamp.timestamp() as u64;
        
        // ハッシュ値とコミットメントをField要素に変換
        let activity_hash_fr = Fr::from_be_bytes_mod_order(&activity_hash);
        let user_commitment_fr = Fr::from_be_bytes_mod_order(&user_commitment);
        
        Self {
            timestamp: timestamp_u64,
            activity_hash: activity_hash_fr,
            user_commitment: user_commitment_fr,
        }
    }
}

// 検証システムの実装
pub struct ActivityVerifier {
    proving_key: ark_groth16::ProvingKey<Bn254>,
    verifying_key: ark_groth16::PreparedVerifyingKey<Bn254>,
}

impl ActivityVerifier {
    // 新しい検証システムの初期化
    pub fn new() -> Self {
        let rng = &mut test_rng();
        
        // ダミーの回路でパラメータを生成
        let circuit = ActivityCircuit::new(
            Utc::now(),
            [0u8; 32],
            [0u8; 32],
        );
        
        // 証明キーと検証キーの生成
        let params = generate_random_parameters::<Bn254, _, _>(circuit, rng).unwrap();
        let verifying_key = prepare_verifying_key(&params.vk);
        
        Self {
            proving_key: params,
            verifying_key,
        }
    }
    
    // 証明の生成
    pub fn generate_proof(&self, activity_data: &ActivityData) -> Result<ark_groth16::Proof<Bn254>, &'static str> {
        let rng = &mut test_rng();
        
        // 回路の作成
        let circuit = ActivityCircuit::new(
            activity_data.timestamp,
            activity_data.activity_hash,
            activity_data.user_commitment,
        );
        
        // 証明の生成
        create_random_proof(circuit, &self.proving_key, rng)
            .map_err(|_| "Failed to generate proof")
    }
    
    // 証明の検証
    pub fn verify_proof(
        &self,
        proof: &ark_groth16::Proof<Bn254>,
        public_inputs: &[Fr],
    ) -> bool {
        verify_proof(
            &self.verifying_key,
            proof,
            public_inputs,
        )
        .unwrap_or(false)
    }
    
    // 行動の検証（メインの検証ロジック）
    pub fn verify_activity(&self, activity_data: &ActivityData) -> bool {
        // 1ヶ月前の日時を計算
        let one_month_ago = Utc::now() - Duration::days(30);
        
        // タイムスタンプの検証
        if activity_data.timestamp < one_month_ago {
            return false;
        }
        
        // 証明の生成
        let proof = match self.generate_proof(activity_data) {
            Ok(p) => p,
            Err(_) => return false,
        };
        
        // 公開入力の準備
        let public_inputs = vec![
            Fr::from(activity_data.timestamp.timestamp() as u64),
            Fr::from_be_bytes_mod_order(&activity_data.activity_hash),
        ];
        
        // 証明の検証
        self.verify_proof(&proof, &public_inputs)
    }
}

// ユーティリティ関数
pub fn hash_activity(activity: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(activity.as_bytes());
    hasher.finalize().into()
}

// 使用例
fn main() {
    // 検証システムの初期化
    let verifier = ActivityVerifier::new();
    
    // テスト用の行動データの作成
    let activity_data = ActivityData {
        timestamp: Utc::now(),
        activity_hash: hash_activity("some_activity"),
        user_commitment: [0u8; 32], // 実際の実装ではユーザー固有の値を使用
    };
    
    // 検証の実行
    let is_valid = verifier.verify_activity(&activity_data);
    println!("検証結果: {}", is_valid);
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_recent_activity_verification() {
        let verifier = ActivityVerifier::new();
        
        // 有効な行動データのテスト
        let valid_activity = ActivityData {
            timestamp: Utc::now(),
            activity_hash: hash_activity("valid_activity"),
            user_commitment: [1u8; 32],
        };
        
        assert!(verifier.verify_activity(&valid_activity));
        
        // 1ヶ月以上前の行動データのテスト
        let old_activity = ActivityData {
            timestamp: Utc::now() - Duration::days(31),
            activity_hash: hash_activity("old_activity"),
            user_commitment: [1u8; 32],
        };
        
        assert!(!verifier.verify_activity(&old_activity));
    }
}