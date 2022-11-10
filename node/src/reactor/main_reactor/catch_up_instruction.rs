use std::time::Duration;

use crate::{effect::Effects, reactor::main_reactor::MainEvent};

pub(super) enum CatchUpInstruction {
    Do(Duration, Effects<MainEvent>),
    CheckLater(String, Duration),
    Fatal(String),
    ShutdownForUpgrade,
    CaughtUp,
    CommitGenesis,
    CommitUpgrade,
}
