import { startVaultHost } from "../host";

const script = document.currentScript as HTMLScriptElement | null;
startVaultHost({ backendUrl: script?.dataset.backend ?? location.origin });
