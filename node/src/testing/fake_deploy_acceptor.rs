//! The `FakeDeployAcceptor` behaves as per the real `DeployAcceptor` but without any deploy
//! verification being performed.
//!
//! When a new deploy is passed in, it is unconditionally accepted.  This means that the
//! `FakeDeployAcceptor` puts the deploy to storage, and once that has completed, announces the
//! deploy if the storage result indicates it's a new deploy.

use tracing::debug;

use casper_types::Timestamp;

pub(crate) use crate::components::deploy_acceptor::{Error, Event};
use crate::{
    components::{deploy_acceptor::EventMetadata, Component},
    effect::{
        announcements::DeployAcceptorAnnouncement, requests::StorageRequest, EffectBuilder,
        EffectExt, Effects, Responder,
    },
    types::Deploy,
    utils::Source,
    NodeRng,
};

const COMPONENT_NAME: &str = "fake_deploy_acceptor";

pub(crate) trait ReactorEventT:
    From<Event> + From<DeployAcceptorAnnouncement> + From<StorageRequest> + Send
{
}

impl<REv> ReactorEventT for REv where
    REv: From<Event> + From<DeployAcceptorAnnouncement> + From<StorageRequest> + Send
{
}

#[derive(Debug)]
pub struct FakeDeployAcceptor {
    is_active: bool,
}

impl FakeDeployAcceptor {
    pub(crate) fn new() -> Self {
        FakeDeployAcceptor { is_active: true }
    }

    pub(crate) fn set_active(&mut self, new_setting: bool) {
        self.is_active = new_setting;
    }

    fn accept<REv: ReactorEventT>(
        &mut self,
        effect_builder: EffectBuilder<REv>,
        deploy: Box<Deploy>,
        source: Source,
        maybe_responder: Option<Responder<Result<(), Error>>>,
    ) -> Effects<Event> {
        let verification_start_timestamp = Timestamp::now();
        let event_metadata = EventMetadata::new(deploy.clone(), source, maybe_responder);
        effect_builder
            .put_deploy_to_storage(Box::new(*deploy))
            .event(move |is_new| Event::PutToStorageResult {
                event_metadata,
                is_new,
                verification_start_timestamp,
            })
    }

    fn handle_put_to_storage<REv: ReactorEventT>(
        &self,
        effect_builder: EffectBuilder<REv>,
        event_metadata: EventMetadata,
        is_new: bool,
    ) -> Effects<Event> {
        let EventMetadata {
            deploy,
            source,
            maybe_responder,
        } = event_metadata;
        let mut effects = Effects::new();
        if is_new {
            effects.extend(
                effect_builder
                    .announce_new_deploy_accepted(deploy, source)
                    .ignore(),
            );
        }

        if let Some(responder) = maybe_responder {
            effects.extend(responder.respond(Ok(())).ignore());
        }
        effects
    }
}

impl<REv: ReactorEventT> Component<REv> for FakeDeployAcceptor {
    type Event = Event;

    fn handle_event(
        &mut self,
        effect_builder: EffectBuilder<REv>,
        _rng: &mut NodeRng,
        event: Self::Event,
    ) -> Effects<Self::Event> {
        if !self.is_active {
            debug!(?event, "FakeDeployAcceptor: not active - ignoring event");
            return Effects::new();
        }
        debug!(?event, "FakeDeployAcceptor: handling event");
        match event {
            Event::Accept {
                deploy,
                source,
                maybe_responder,
            } => self.accept(effect_builder, deploy, source, maybe_responder),
            Event::PutToStorageResult {
                event_metadata,
                is_new,
                ..
            } => self.handle_put_to_storage(effect_builder, event_metadata, is_new),
            _ => unimplemented!("unexpected {:?}", event),
        }
    }

    fn name(&self) -> &str {
        COMPONENT_NAME
    }
}
