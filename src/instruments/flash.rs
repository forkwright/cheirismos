//! Geometry-bound SPI-NOR command planning.
//!
//! A plan is deliberately only valid after a device has supplied JEDEC/SFDP facts
//! and the caller has matched those facts to a commissioned profile. It cannot
//! infer capacity, erase size, or an address mode from a target name.

use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressMode {
    ThreeByte,
    FourByte,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlashGeometry {
    capacity_bytes: u64,
    page_bytes: u32,
    erase_bytes: u32,
    address_mode: AddressMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlashLayoutError {
    ZeroCapacity,
    ZeroPage,
    ZeroErase,
    UnsupportedThreeByteCapacity {
        capacity_bytes: u64,
    },
    UnsupportedFourByteCapacity {
        capacity_bytes: u64,
    },
    UnsupportedEraseBytes {
        erase_bytes: u32,
    },
    OutOfBounds {
        offset: u64,
        length: u32,
        capacity_bytes: u64,
    },
    EraseUnaligned {
        offset: u64,
        length: u32,
        erase_bytes: u32,
    },
}

impl Display for FlashLayoutError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroCapacity => formatter.write_str("flash capacity must be non-zero"),
            Self::ZeroPage => formatter.write_str("flash page size must be non-zero"),
            Self::ZeroErase => formatter.write_str("flash erase size must be non-zero"),
            Self::UnsupportedThreeByteCapacity { capacity_bytes } => write!(
                formatter,
                "three-byte addressing cannot represent {capacity_bytes}-byte flash"
            ),
            Self::UnsupportedFourByteCapacity { capacity_bytes } => write!(
                formatter,
                "four-byte addressing cannot represent {capacity_bytes}-byte flash"
            ),
            Self::UnsupportedEraseBytes { erase_bytes } => write!(
                formatter,
                "the qualified NOR profile supports only 4096-byte erase sectors, not {erase_bytes}"
            ),
            Self::OutOfBounds {
                offset,
                length,
                capacity_bytes,
            } => write!(
                formatter,
                "range {offset}..{} exceeds {capacity_bytes}-byte flash",
                offset.saturating_add(u64::from(*length))
            ),
            Self::EraseUnaligned {
                offset,
                length,
                erase_bytes,
            } => write!(
                formatter,
                "erase {offset}..{} is not aligned to {erase_bytes}-byte sectors",
                offset.saturating_add(u64::from(*length))
            ),
        }
    }
}

impl std::error::Error for FlashLayoutError {}

impl FlashGeometry {
    pub fn try_new(
        capacity_bytes: u64,
        page_bytes: u32,
        erase_bytes: u32,
        address_mode: AddressMode,
    ) -> Result<Self, FlashLayoutError> {
        if capacity_bytes == 0 {
            return Err(FlashLayoutError::ZeroCapacity);
        }
        if page_bytes == 0 {
            return Err(FlashLayoutError::ZeroPage);
        }
        if erase_bytes == 0 {
            return Err(FlashLayoutError::ZeroErase);
        }
        if erase_bytes != 4096 {
            return Err(FlashLayoutError::UnsupportedEraseBytes { erase_bytes });
        }
        if matches!(address_mode, AddressMode::ThreeByte) && capacity_bytes > 0x01_00_00_00 {
            return Err(FlashLayoutError::UnsupportedThreeByteCapacity { capacity_bytes });
        }
        if matches!(address_mode, AddressMode::FourByte) && capacity_bytes > 0x1_00_00_00_00 {
            return Err(FlashLayoutError::UnsupportedFourByteCapacity { capacity_bytes });
        }
        Ok(Self {
            capacity_bytes,
            page_bytes,
            erase_bytes,
            address_mode,
        })
    }

    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }

    pub fn validate_range(&self, offset: u64, length: u32) -> Result<(), FlashLayoutError> {
        let end = offset
            .checked_add(u64::from(length))
            .ok_or(FlashLayoutError::OutOfBounds {
                offset,
                length,
                capacity_bytes: self.capacity_bytes,
            })?;
        if end > self.capacity_bytes {
            return Err(FlashLayoutError::OutOfBounds {
                offset,
                length,
                capacity_bytes: self.capacity_bytes,
            });
        }
        Ok(())
    }

    pub fn validate_erase(&self, offset: u64, length: u32) -> Result<(), FlashLayoutError> {
        self.validate_range(offset, length)?;
        let erase_bytes = u64::from(self.erase_bytes);
        if !offset.is_multiple_of(erase_bytes) || !u64::from(length).is_multiple_of(erase_bytes) {
            return Err(FlashLayoutError::EraseUnaligned {
                offset,
                length,
                erase_bytes: self.erase_bytes,
            });
        }
        Ok(())
    }

    fn address(&self, offset: u64) -> Vec<u8> {
        match self.address_mode {
            AddressMode::ThreeByte => vec![(offset >> 16) as u8, (offset >> 8) as u8, offset as u8],
            AddressMode::FourByte => vec![
                (offset >> 24) as u8,
                (offset >> 16) as u8,
                (offset >> 8) as u8,
                offset as u8,
            ],
        }
    }

    fn opcodes(&self) -> (u8, u8, u8) {
        match self.address_mode {
            AddressMode::ThreeByte => (0x03, 0x02, 0x20),
            // WHY: these dedicated opcodes avoid assuming a persistent Enter-4BA
            // device mode on an unqualified target.
            AddressMode::FourByte => (0x13, 0x12, 0x21),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NorOperation {
    Identify,
    Read { offset: u64, length: u32 },
    Erase { offset: u64, length: u32 },
    Write { offset: u64, bytes: Vec<u8> },
    Verify { offset: u64, expected: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NorCommand {
    Transfer { bytes: Vec<u8>, read_bytes: u32 },
    PollBusyClear,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NorPlan {
    pub commands: Vec<NorCommand>,
    pub expected_read_bytes: u32,
}

impl NorPlan {
    pub fn for_operation(
        geometry: &FlashGeometry,
        operation: &NorOperation,
    ) -> Result<Self, FlashLayoutError> {
        match operation {
            NorOperation::Identify => Ok(Self {
                commands: vec![
                    NorCommand::Transfer {
                        bytes: vec![0x9F],
                        read_bytes: 3,
                    },
                    NorCommand::Transfer {
                        bytes: vec![0x5A, 0, 0, 0, 0],
                        read_bytes: 256,
                    },
                ],
                expected_read_bytes: 259,
            }),
            NorOperation::Read { offset, length } => {
                geometry.validate_range(*offset, *length)?;
                let (read_opcode, _, _) = geometry.opcodes();
                let mut bytes = vec![read_opcode];
                bytes.extend(geometry.address(*offset));
                Ok(Self {
                    commands: vec![NorCommand::Transfer {
                        bytes,
                        read_bytes: *length,
                    }],
                    expected_read_bytes: *length,
                })
            }
            NorOperation::Erase { offset, length } => {
                geometry.validate_erase(*offset, *length)?;
                let (_, _, erase_opcode) = geometry.opcodes();
                let mut commands = Vec::new();
                for sector in (0..u64::from(*length)).step_by(geometry.erase_bytes as usize) {
                    commands.push(NorCommand::Transfer {
                        bytes: vec![0x06],
                        read_bytes: 0,
                    });
                    let mut erase = vec![erase_opcode];
                    erase.extend(geometry.address(offset.checked_add(sector).ok_or(
                        FlashLayoutError::OutOfBounds {
                            offset: *offset,
                            length: *length,
                            capacity_bytes: geometry.capacity_bytes,
                        },
                    )?));
                    commands.push(NorCommand::Transfer {
                        bytes: erase,
                        read_bytes: 0,
                    });
                    commands.push(NorCommand::PollBusyClear);
                }
                Ok(Self {
                    commands,
                    expected_read_bytes: 0,
                })
            }
            NorOperation::Write { offset, bytes } => {
                let length =
                    u32::try_from(bytes.len()).map_err(|_| FlashLayoutError::OutOfBounds {
                        offset: *offset,
                        length: u32::MAX,
                        capacity_bytes: geometry.capacity_bytes,
                    })?;
                geometry.validate_range(*offset, length)?;
                let (_, program_opcode, _) = geometry.opcodes();
                let mut commands = Vec::new();
                let mut cursor = 0usize;
                while cursor < bytes.len() {
                    let write_offset =
                        offset
                            .checked_add(cursor as u64)
                            .ok_or(FlashLayoutError::OutOfBounds {
                                offset: *offset,
                                length,
                                capacity_bytes: geometry.capacity_bytes,
                            })?;
                    let page_remaining = usize::try_from(
                        u64::from(geometry.page_bytes)
                            - (write_offset % u64::from(geometry.page_bytes)),
                    )
                    .unwrap_or(0);
                    let count = page_remaining.min(bytes.len() - cursor);
                    commands.push(NorCommand::Transfer {
                        bytes: vec![0x06],
                        read_bytes: 0,
                    });
                    let mut page = vec![program_opcode];
                    page.extend(geometry.address(write_offset));
                    let page_data = bytes
                        .get(cursor..)
                        .and_then(|remaining| remaining.get(..count))
                        .ok_or(FlashLayoutError::OutOfBounds {
                            offset: *offset,
                            length,
                            capacity_bytes: geometry.capacity_bytes,
                        })?;
                    page.extend_from_slice(page_data);
                    commands.push(NorCommand::Transfer {
                        bytes: page,
                        read_bytes: 0,
                    });
                    commands.push(NorCommand::PollBusyClear);
                    cursor += count;
                }
                Ok(Self {
                    commands,
                    expected_read_bytes: 0,
                })
            }
            NorOperation::Verify { offset, expected } => {
                let length =
                    u32::try_from(expected.len()).map_err(|_| FlashLayoutError::OutOfBounds {
                        offset: *offset,
                        length: u32::MAX,
                        capacity_bytes: geometry.capacity_bytes,
                    })?;
                Self::for_operation(
                    geometry,
                    &NorOperation::Read {
                        offset: *offset,
                        length,
                    },
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AddressMode, FlashGeometry, FlashLayoutError, NorCommand, NorOperation, NorPlan};

    fn geometry() -> FlashGeometry {
        FlashGeometry::try_new(8192, 256, 4096, AddressMode::ThreeByte)
            .unwrap_or_else(|error| panic!("valid geometry: {error}"))
    }

    #[test]
    fn write_never_crosses_page_boundary() {
        let plan = NorPlan::for_operation(
            &geometry(),
            &NorOperation::Write {
                offset: 250,
                bytes: vec![0xA5; 12],
            },
        )
        .unwrap_or_else(|error| panic!("valid write: {error}"));
        let writes = plan
            .commands
            .iter()
            .filter_map(|command| match command {
                NorCommand::Transfer { bytes, .. } if bytes.first() == Some(&0x02) => Some(bytes),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[0].len(), 1 + 3 + 6);
        assert_eq!(writes[1].len(), 1 + 3 + 6);
    }

    #[test]
    fn refuses_unaligned_erase() {
        let result = NorPlan::for_operation(
            &geometry(),
            &NorOperation::Erase {
                offset: 1,
                length: 4096,
            },
        );
        assert!(matches!(
            result,
            Err(FlashLayoutError::EraseUnaligned { .. })
        ));
    }

    #[test]
    fn four_byte_mode_is_required_for_large_flash() {
        let result = FlashGeometry::try_new(0x01_00_00_01, 256, 4096, AddressMode::ThreeByte);
        assert!(matches!(
            result,
            Err(FlashLayoutError::UnsupportedThreeByteCapacity { .. })
        ));
    }

    #[test]
    fn four_byte_profile_uses_explicit_qualified_opcodes() {
        let geometry = FlashGeometry::try_new(0x01_00_00_00, 256, 4096, AddressMode::FourByte)
            .unwrap_or_else(|error| panic!("valid four-byte geometry: {error}"));
        let read = NorPlan::for_operation(
            &geometry,
            &NorOperation::Read {
                offset: 0,
                length: 1,
            },
        )
        .unwrap_or_else(|error| panic!("read plan: {error}"));
        let erase = NorPlan::for_operation(
            &geometry,
            &NorOperation::Erase {
                offset: 0,
                length: 4096,
            },
        )
        .unwrap_or_else(|error| panic!("erase plan: {error}"));
        assert!(
            matches!(read.commands.first(), Some(NorCommand::Transfer { bytes, .. }) if bytes.first() == Some(&0x13))
        );
        assert!(erase.commands.iter().any(|command| matches!(command, NorCommand::Transfer { bytes, .. } if bytes.first() == Some(&0x21))));
    }

    #[test]
    fn rejects_unqualified_erase_geometry() {
        let result = FlashGeometry::try_new(8192, 256, 65536, AddressMode::ThreeByte);
        assert!(matches!(
            result,
            Err(FlashLayoutError::UnsupportedEraseBytes { .. })
        ));
    }
}
