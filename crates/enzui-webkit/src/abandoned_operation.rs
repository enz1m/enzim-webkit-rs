use core::cell::Cell;

pub(crate) struct AbandonedOperationFields<'a, Session, Witness> {
    pub(crate) session: &'a mut *mut Session,
    pub(crate) session_witness: &'a Cell<*mut Witness>,
    pub(crate) cancellable_witness: &'a Cell<*mut Witness>,
    pub(crate) abandoned: &'a Cell<bool>,
}

pub(crate) trait AbandonedOperationState {
    type Session;
    type Witness;

    fn abandoned_operation_fields(
        &mut self,
    ) -> AbandonedOperationFields<'_, Self::Session, Self::Witness>;

    fn is_abandoned(&self) -> bool;
}

pub(crate) struct WitnessLocations<Witness> {
    pub(crate) session: *mut *mut Witness,
    pub(crate) cancellable: *mut *mut Witness,
}

// `state_ptr` must be valid, aligned, and exclusively accessible for this call;
// its allocation must remain live and unmoved while the returned locations are used.
pub(crate) unsafe fn transfer_abandoned_ownership<State>(
    state_ptr: *mut State,
    session: *mut State::Session,
    session_witness: *mut State::Witness,
    cancellable_witness: *mut State::Witness,
) -> WitnessLocations<State::Witness>
where
    State: AbandonedOperationState,
{
    // SAFETY: the caller guarantees unique access to the live state.
    let state = unsafe { &mut *state_ptr };
    let fields = state.abandoned_operation_fields();
    *fields.session = session;
    fields.session_witness.set(session_witness);
    fields.cancellable_witness.set(cancellable_witness);
    fields.abandoned.set(true);
    WitnessLocations {
        session: fields.session_witness.as_ptr(),
        cancellable: fields.cancellable_witness.as_ptr(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestState {
        session: *mut u8,
        session_witness: Cell<*mut u8>,
        cancellable_witness: Cell<*mut u8>,
        abandoned: Cell<bool>,
    }

    impl AbandonedOperationState for TestState {
        type Session = u8;
        type Witness = u8;

        fn abandoned_operation_fields(
            &mut self,
        ) -> AbandonedOperationFields<'_, Self::Session, Self::Witness> {
            AbandonedOperationFields {
                session: &mut self.session,
                session_witness: &self.session_witness,
                cancellable_witness: &self.cancellable_witness,
                abandoned: &self.abandoned,
            }
        }

        fn is_abandoned(&self) -> bool {
            self.abandoned.get()
        }
    }

    #[test]
    fn raw_transfer_updates_all_ownership_fields() {
        let mut state = TestState {
            session: core::ptr::null_mut(),
            session_witness: Cell::new(core::ptr::null_mut()),
            cancellable_witness: Cell::new(core::ptr::null_mut()),
            abandoned: Cell::new(false),
        };
        let mut session_sentinel = 0_u8;
        let mut session_witness_sentinel = 0_u8;
        let mut cancellable_witness_sentinel = 0_u8;
        let session = &raw mut session_sentinel;
        let session_witness = &raw mut session_witness_sentinel;
        let cancellable_witness = &raw mut cancellable_witness_sentinel;

        assert_ne!(session, session_witness);
        assert_ne!(session, cancellable_witness);
        assert_ne!(session_witness, cancellable_witness);

        // SAFETY: `state` is live and exclusively borrowed for this call.
        let witnesses = unsafe {
            transfer_abandoned_ownership(
                &raw mut state,
                session,
                session_witness,
                cancellable_witness,
            )
        };

        assert_eq!(state.session, session);
        assert_eq!(state.session_witness.get(), session_witness);
        assert_eq!(state.cancellable_witness.get(), cancellable_witness);
        assert!(state.is_abandoned());
        assert_eq!(witnesses.session, state.session_witness.as_ptr());
        assert_eq!(witnesses.cancellable, state.cancellable_witness.as_ptr());
    }
}
