use serde_json::json;

use crate::domain::Operation;
use crate::instruments::Simulator;
use crate::supervisor::{ArtifactResolver, BackendError};

use super::{ResultData, malformed, source_bytes, transport};

pub(super) fn execute(
    simulator: &mut Simulator,
    operation: &Operation,
    artifacts: &dyn ArtifactResolver,
    reconcile: bool,
) -> Result<ResultData, BackendError> {
    let mut result = match operation {
        Operation::InstrumentStatus { .. } => ResultData::observation(json!(simulator.observe())),
        Operation::FlashIdentify { .. } => ResultData::observation(
            json!({"implementation":"simulated_nor","capacity_bytes":simulator.observe().flash_bytes}),
        ),
        Operation::FlashRead { offset, length, .. } => ResultData::bytes(
            simulator
                .read_flash(
                    usize::try_from(*offset).map_err(malformed)?,
                    *length as usize,
                )
                .map_err(transport)?,
            json!({"offset":offset}),
        ),
        Operation::FlashWrite {
            offset,
            source,
            length,
            ..
        }
        | Operation::FlashVerify {
            offset,
            source,
            length,
            ..
        } => {
            let bytes = source_bytes(artifacts, source, *length)?;
            let offset = usize::try_from(*offset).map_err(malformed)?;
            if matches!(operation, Operation::FlashWrite { .. }) && !reconcile {
                simulator.write_flash(offset, &bytes).map_err(transport)?;
            }
            let actual = simulator
                .read_flash(offset, bytes.len())
                .map_err(transport)?;
            let matches = actual == bytes;
            ResultData {
                body: json!({"offset":offset,"matches_candidate":matches,"candidate":source}),
                bytes: Some(actual),
                partial: (!matches).then(|| "readback differs from candidate".into()),
            }
        }
        Operation::FlashErase { offset, length, .. } => {
            let offset = usize::try_from(*offset).map_err(malformed)?;
            let length = *length as usize;
            if !reconcile {
                simulator.erase_flash(offset, length).map_err(transport)?;
            }
            let actual = simulator.read_flash(offset, length).map_err(transport)?;
            let blank = actual.iter().all(|byte| *byte == 0xff);
            ResultData {
                body: json!({"offset":offset,"all_erased":blank}),
                bytes: Some(actual),
                partial: (!blank).then(|| "readback is not fully erased".into()),
            }
        }
        Operation::RelayRead { relay, .. } | Operation::RelaySet { relay, .. } => {
            if let Operation::RelaySet { closed, .. } = operation
                && !reconcile
            {
                simulator
                    .set_relay(usize::from(*relay), *closed)
                    .map_err(transport)?;
            }
            let observed = simulator.observe();
            let closed = observed
                .relay_closed
                .get(usize::from(*relay))
                .ok_or_else(|| malformed("simulator relay outside 0..4"))?;
            let mismatch = matches!(operation, Operation::RelaySet { closed: expected, .. } if closed != expected);
            ResultData {
                body: json!({"relay":relay,"closed":closed,"physical_contacts_observed":false}),
                bytes: None,
                partial: mismatch.then(|| "simulated relay state differs from request".into()),
            }
        }
        _ => {
            return Err(malformed(
                "operation is outside this simulator's flash/relay model",
            ));
        }
    };
    result.body["simulated"] = json!(true);
    result.body["reconciliation"] = json!(reconcile);
    result.body["proves_original_actuation"] = json!(false);
    Ok(result)
}
