import { useState } from "react";
import { ActivityIndicator, Modal, Pressable, SafeAreaView, StyleSheet, Text, TextInput, View } from "react-native";
import type { CavosModalConfig } from "./CavosProvider";
import { useCavos } from "./CavosProvider";

export interface CavosAuthModalProps {
  open: boolean;
  onClose(): void;
  config: CavosModalConfig;
}

export function CavosAuthModal({ open, onClose, config }: CavosAuthModalProps) {
  const cavos = useCavos();
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [generatedRecoveryCode, setGeneratedRecoveryCode] = useState("");
  const [otpSent, setOtpSent] = useState(false);
  const [busy, setBusy] = useState(false);
  const providers = config.providers ?? ["google", "apple", "email"];
  const color = config.primaryColor ?? "#111111";

  async function run(action: () => Promise<unknown>) {
    setBusy(true);
    cavos.clearAuthError();
    try { await action(); }
    finally { setBusy(false); }
  }

  const approval = cavos.walletStatus.needsDeviceApproval;
  const ready = cavos.walletStatus.isReady;

  return <Modal visible={open} animationType="slide" presentationStyle="pageSheet" onRequestClose={onClose}>
    <SafeAreaView style={styles.safe}>
      <View style={styles.card}>
        <View style={styles.header}>
          <Text style={styles.title}>{config.appName ?? "Sign in with Cavos"}</Text>
          <Pressable onPress={onClose}><Text style={styles.close}>Close</Text></Pressable>
        </View>

        {busy || cavos.isLoading || cavos.walletStatus.isDeploying ? <ActivityIndicator color={color} /> : null}
        {cavos.authError ? <Text style={styles.error}>{cavos.authError}</Text> : null}

        {!cavos.isAuthenticated && !busy ? <View style={styles.stack}>
          {providers.includes("google") ? <Button label="Continue with Google" color={color} onPress={() => run(() => cavos.login("google"))} /> : null}
          {providers.includes("apple") ? <Button label="Continue with Apple" color={color} onPress={() => run(() => cavos.login("apple"))} /> : null}
          {providers.includes("email") ? <>
            <TextInput style={styles.input} value={email} onChangeText={setEmail} keyboardType="email-address" autoCapitalize="none" placeholder="Email" />
            {config.emailMode === "otp" ? <>
              {otpSent ? <TextInput style={styles.input} value={code} onChangeText={setCode} keyboardType="number-pad" placeholder="Verification code" /> : null}
              <Button color={color} label={otpSent ? "Verify code" : "Send code"} onPress={() => run(async () => {
                if (otpSent) await cavos.verifyOtp(email, code);
                else { await cavos.sendOtp(email); setOtpSent(true); }
              })} />
            </> : <Button color={color} label="Email me a sign-in link" onPress={() => run(() => cavos.sendMagicLink(email))} />}
          </> : null}
        </View> : null}

        {approval && !busy ? <View style={styles.stack}>
          <Text style={styles.body}>This is a new device. Approve it with your passkey, recovery code, or another authorized device.</Text>
          {cavos.capabilities?.passkey ? <Button color={color} label="Approve with passkey" onPress={() => run(cavos.approveDeviceWithPasskey)} /> : null}
          <TextInput style={styles.input} value={recoveryCode} onChangeText={setRecoveryCode} autoCapitalize="characters" placeholder="Recovery code" />
          <Button color={color} label="Recover this device" onPress={() => run(() => cavos.recover(recoveryCode))} />
          {cavos.walletStatus.awaitingApproval ? <Button color={color} label="Resend approval" onPress={() => run(cavos.resendDeviceApproval)} /> : null}
        </View> : null}

        {ready && !busy ? <View style={styles.stack}>
          <Text style={styles.body}>Wallet ready: {cavos.address}</Text>
          {config.secureStep !== "off" && cavos.walletStatus.isNewAccount ? <>
            {cavos.capabilities?.passkey ? <Button color={color} label="Secure with passkey" onPress={() => run(cavos.enrollPasskeyDefault)} /> : null}
            <Button color={color} label="Create recovery code" onPress={() => run(async () => setGeneratedRecoveryCode(await cavos.setupRecovery()))} />
            {generatedRecoveryCode ? <Text selectable style={styles.recovery}>{generatedRecoveryCode}</Text> : null}
          </> : null}
          <Button color={color} label="Done" onPress={onClose} />
        </View> : null}
      </View>
    </SafeAreaView>
  </Modal>;
}

function Button({ label, color, onPress }: { label: string; color: string; onPress(): void }) {
  return <Pressable accessibilityRole="button" style={[styles.button, { backgroundColor: color }]} onPress={onPress}>
    <Text style={styles.buttonText}>{label}</Text>
  </Pressable>;
}

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: "#f5f5f2" },
  card: { flex: 1, padding: 24, gap: 24 },
  header: { flexDirection: "row", justifyContent: "space-between", alignItems: "center" },
  title: { fontSize: 24, fontWeight: "700", color: "#111" },
  close: { fontSize: 16, color: "#555" },
  stack: { gap: 12 },
  body: { fontSize: 15, lineHeight: 21, color: "#333" },
  error: { color: "#b42318", fontSize: 14 },
  recovery: { color: "#111", fontSize: 15, fontFamily: "monospace", padding: 12, backgroundColor: "#ecece6", borderRadius: 8 },
  input: { borderWidth: 1, borderColor: "#d0d0ca", borderRadius: 10, padding: 14, fontSize: 16, backgroundColor: "white" },
  button: { minHeight: 48, borderRadius: 10, alignItems: "center", justifyContent: "center", paddingHorizontal: 16 },
  buttonText: { color: "white", fontSize: 16, fontWeight: "600" },
});
