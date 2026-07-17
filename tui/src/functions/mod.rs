pub mod keys;
pub mod terminal_control;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputMode {
    NewPeer,
    RenamePeer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmMode {
    Exit,
    DeletePeer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadingMode {
    NewPeer,
    ServerStarted,
}
