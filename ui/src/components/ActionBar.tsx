import { Fragment, useCallback, useEffect, useRef } from "react";
import { MdOutlineContentPasteGo } from "react-icons/md";
import {
  LuCable,
  LuClipboardCheck,
  LuClipboardCopy,
  LuClipboardPaste,
  LuExternalLink,
  LuFolderOpen,
  LuHardDrive,
  LuMaximize,
  LuMic,
  LuMicOff,
  LuScanText,
  LuSettings,
  LuSignal,
  LuTerminal,
  LuX,
} from "react-icons/lu";
import { FaKeyboard } from "react-icons/fa6";
import { Popover, PopoverButton, PopoverPanel } from "@headlessui/react";
import { CommandLineIcon } from "@heroicons/react/20/solid";

import { SplitButtonGroup, SplitButtonPrimary, SplitButtonCaret } from "@components/SplitButton";

import { cx } from "@/cva.config";
import {
  useHidStore,
  useMountMediaStore,
  useRTCStore,
  useSettingsStore,
  useUiStore,
  useVideoStore,
} from "@hooks/stores";
import { useDeviceUiNavigation } from "@hooks/useAppNavigation";
import { Button } from "@components/Button";
import Container from "@components/Container";
import PasteModal from "@components/popovers/PasteModal";
import WakeOnLanModal from "@components/popovers/WakeOnLan/Index";
import MountPopopover from "@components/popovers/MountPopover";
import FileTransferPopover from "@components/popovers/FileTransferPopover";
import ExtensionPopover from "@components/popovers/ExtensionPopover";
import { JsonRpcResponse, useJsonRpc } from "@hooks/useJsonRpc";
import notifications from "@/notifications";
import { m } from "@localizations/messages.js";

export default function Actionbar({
  requestFullscreen,
}: {
  requestFullscreen: () => Promise<void>;
}) {
  const { navigateTo } = useDeviceUiNavigation();
  const { isVirtualKeyboardEnabled, setVirtualKeyboardEnabled } = useHidStore();
  const {
    setDisableVideoFocusTrap,
    terminalType,
    setTerminalType,
    toggleSidebarView,
    isOcrMode,
    setOcrMode,
    usbSerialConsoleEnabled,
    setUsbSerialConsoleEnabled,
    isEmbedMode,
  } = useUiStore();
  const { remoteVirtualMediaState } = useMountMediaStore();
  const { width: videoWidth, height: videoHeight } = useVideoStore();
  const { developerMode, clipboardAutoSync, setClipboardAutoSync } = useSettingsStore();
  const { audioTransceiver, micEnabled, setMicEnabled } = useRTCStore();
  const { send } = useJsonRpc();

  useEffect(() => {
    send("getUsbDevices", {}, (resp: JsonRpcResponse) => {
      if ("error" in resp) return;
      const devices = resp.result as { serial_console?: boolean };
      setUsbSerialConsoleEnabled(devices.serial_console === true);
    });
  }, [send, setUsbSerialConsoleEnabled]);

  const lastSentHashRef = useRef<string | null>(null);
  const lastRecvHashRef = useRef<string | null>(null);

  const readRichClipboard = useCallback(async () => {
    if (!navigator.clipboard?.read) return null;
    const items = await navigator.clipboard.read();
    return await Promise.all(
      items.map(async item => ({
        types: await Promise.all(
          item.types.map(async mime => {
            const blob = await item.getType(mime);
            const data = mime.startsWith("text/")
              ? await blob.text()
              : await new Promise<string>(res => {
                  const r = new FileReader();
                  r.onload = () => res((r.result as string).split(",")[1]);
                  r.readAsDataURL(blob);
                });
            return { mime, data };
          }),
        ),
      })),
    );
  }, []);

  const sendClipboardToTarget = useCallback(
    async (force = false) => {
      const payload = await readRichClipboard();
      if (!payload?.length) return;
      const hash = JSON.stringify(payload).length + "|" + (payload[0]?.types[0]?.data.slice(0, 32) ?? "");
      if (!force && hash === lastSentHashRef.current) return;
      const resp = await fetch("/api/clip/out", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (resp.ok) {
        lastSentHashRef.current = hash;
        if (force) notifications.success(m.action_bar_clipboard_auto_synced());
      }
    },
    [readRichClipboard],
  );

  const handleClipboardSend = useCallback(async () => {
    try {
      await sendClipboardToTarget(true);
    } catch {
      notifications.error(m.action_bar_clipboard_no_permission());
    }
  }, [sendClipboardToTarget]);

  type RichClipItem = { types: { mime: string; data: string }[] };

  const writeRichClipboard = useCallback(async (items: RichClipItem[]) => {
    if (!items?.length) return;
    if (navigator.clipboard?.write) {
      const clipItems = items.map(item => {
        const map: Record<string, Blob> = {};
        item.types.forEach(t => {
          if (t.mime.startsWith("text/")) {
            map[t.mime] = new Blob([t.data], { type: t.mime });
          } else {
            const bin = atob(t.data);
            const bytes = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
            map[t.mime] = new Blob([bytes], { type: t.mime });
          }
        });
        return new ClipboardItem(map);
      });
      await navigator.clipboard.write(clipItems);
    } else {
      for (const item of items) {
        const plain = item.types.find(t => t.mime === "text/plain");
        if (plain) { await navigator.clipboard.writeText(plain.data); return; }
      }
    }
  }, []);

  const handleClipboardReceive = useCallback(async () => {
    try {
      const resp = await fetch("/api/clip");
      const items = (await resp.json()) as RichClipItem[];
      await writeRichClipboard(items);
      notifications.success(m.action_bar_clipboard_sync_receive_success());
    } catch {
      notifications.error(m.action_bar_clipboard_no_permission());
    }
  }, [writeRichClipboard]);

  useEffect(() => {
    if (!clipboardAutoSync) return;
    const autoSyncClipboardPermissionShownRef = { shown: false };
    const sync = async () => {
      if (document.hidden) return;
      try {
        await sendClipboardToTarget(false);
      } catch (e) {
        if (e instanceof DOMException && e.name === "NotAllowedError" && !autoSyncClipboardPermissionShownRef.shown) {
          autoSyncClipboardPermissionShownRef.shown = true;
          notifications.error(m.action_bar_clipboard_no_permission());
        }
      }
    };
    const onVisible = () => { if (!document.hidden) setTimeout(() => void sync(), 200); };
    const onFocus = () => setTimeout(() => void sync(), 200);
    const onCopy = () => setTimeout(() => void sync(), 100);
    document.addEventListener("visibilitychange", onVisible);
    window.addEventListener("focus", onFocus);
    document.addEventListener("copy", onCopy);

    // Poll target's clipboard (/api/clip) and auto-write to operator clipboard when it changes
    const pollTargetClipboard = async () => {
      try {
        const resp = await fetch("/api/clip");
        if (!resp.ok) return;
        const items = (await resp.json()) as RichClipItem[];
        if (!items?.length) return;
        const hash = JSON.stringify(items).length + "|" + (items[0]?.types[0]?.data.slice(0, 32) ?? "");
        if (hash === lastRecvHashRef.current) return;
        lastRecvHashRef.current = hash;
        await writeRichClipboard(items);
      } catch {
        // ignore — network errors are normal
      }
    };
    const pollInterval = setInterval(() => void pollTargetClipboard(), 3000);

    return () => {
      document.removeEventListener("visibilitychange", onVisible);
      window.removeEventListener("focus", onFocus);
      document.removeEventListener("copy", onCopy);
      clearInterval(pollInterval);
    };
  }, [clipboardAutoSync, sendClipboardToTarget, writeRichClipboard]);

  const handleMicToggle = useCallback(async () => {
    if (!audioTransceiver) return;
    if (micEnabled) {
      const sender = audioTransceiver.sender;
      if (sender.track) sender.track.enabled = false;
      setMicEnabled(false);
    } else {
      try {
        if (audioTransceiver.sender.track) {
          audioTransceiver.sender.track.enabled = true;
        } else {
          const stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
          const [track] = stream.getAudioTracks();
          await audioTransceiver.sender.replaceTrack(track);
        }
        setMicEnabled(true);
      } catch {
        notifications.error(m.action_bar_mic_permission_denied());
      }
    }
  }, [audioTransceiver, micEnabled, setMicEnabled]);

  // This is the only way to get a reliable state change for the popover
  // at time of writing this there is no mount, or unmount event for the popover
  const isOpen = useRef<boolean>(false);
  const checkIfStateChanged = useCallback(
    (open: boolean) => {
      if (open !== isOpen.current) {
        isOpen.current = open;
        if (!open) {
          setTimeout(() => {
            setDisableVideoFocusTrap(false);
            console.debug("Popover is closing. Returning focus trap to video");
          }, 0);
        }
      }
    },
    [setDisableVideoFocusTrap],
  );

  return (
    <Container className="border-b border-b-slate-800/20 bg-white dark:border-b-slate-300/20 dark:bg-slate-900">
      <div
        onKeyUp={e => e.stopPropagation()}
        onKeyDown={e => e.stopPropagation()}
        className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 py-1.5"
      >
        <div className="relative flex flex-wrap items-center gap-x-2 gap-y-2">
          {developerMode && usbSerialConsoleEnabled ? (
            <SplitButtonGroup>
              <SplitButtonPrimary
                icon={({ className }) => <CommandLineIcon className={className} />}
                label={m.kvm_terminal()}
                onClick={() => setTerminalType(terminalType === "kvm" ? "none" : "kvm")}
              />
              <SplitButtonCaret
                menuItems={[
                  {
                    label: "USB Serial Console",
                    icon: LuTerminal,
                    onClick: () => setTerminalType(terminalType === "cdcacm" ? "none" : "cdcacm"),
                    active: terminalType === "cdcacm",
                  },
                ]}
              />
            </SplitButtonGroup>
          ) : developerMode ? (
            <Button
              size="XS"
              theme="light"
              text={m.kvm_terminal()}
              LeadingIcon={({ className }) => <CommandLineIcon className={className} />}
              onClick={() => setTerminalType(terminalType === "kvm" ? "none" : "kvm")}
            />
          ) : usbSerialConsoleEnabled ? (
            <Button
              size="XS"
              theme="light"
              text="USB Serial Console"
              LeadingIcon={LuTerminal}
              onClick={() => setTerminalType(terminalType === "cdcacm" ? "none" : "cdcacm")}
            />
          ) : null}
          <Popover>
            <SplitButtonGroup>
              <PopoverButton
                as={SplitButtonPrimary}
                icon={MdOutlineContentPasteGo}
                label={m.paste_text()}
                onClick={() => setDisableVideoFocusTrap(true)}
              />
              <SplitButtonCaret
                menuItems={[
                  {
                    label: m.action_bar_copy_text(),
                    icon: LuScanText,
                    onClick: () => setOcrMode(!isOcrMode),
                    active: isOcrMode,
                    disabled: videoWidth === 0 || videoHeight === 0,
                  },
                  {
                    label: m.action_bar_clipboard_sync_send(),
                    icon: LuClipboardCopy,
                    onClick: () => void handleClipboardSend(),
                  },
                  {
                    label: m.action_bar_clipboard_sync_receive(),
                    icon: LuClipboardPaste,
                    onClick: () => void handleClipboardReceive(),
                  },
                  {
                    label: clipboardAutoSync
                      ? m.action_bar_clipboard_auto_sync_on()
                      : m.action_bar_clipboard_auto_sync_off(),
                    icon: LuClipboardCheck,
                    onClick: async () => {
                      if (!clipboardAutoSync) {
                        try {
                          await readRichClipboard();
                          setClipboardAutoSync(true);
                        } catch {
                          notifications.error(m.action_bar_clipboard_no_permission());
                        }
                      } else {
                        setClipboardAutoSync(false);
                      }
                    },
                    active: clipboardAutoSync,
                  },
                ]}
              />
            </SplitButtonGroup>
            <PopoverPanel
              anchor="bottom start"
              transition
              className={cx(
                "z-10 flex w-[420px] origin-top flex-col overflow-visible!",
                "flex origin-top flex-col transition duration-300 ease-out data-closed:translate-y-8 data-closed:opacity-0",
              )}
            >
              {({ open }) => {
                checkIfStateChanged(open);
                return (
                  <div className="mx-auto w-full max-w-xl">
                    <PasteModal />
                  </div>
                );
              }}
            </PopoverPanel>
          </Popover>
          <div className="relative">
            <Popover>
              <PopoverButton as={Fragment}>
                <Button
                  size="XS"
                  theme="light"
                  text={m.action_bar_virtual_media()}
                  LeadingIcon={({ className }) => {
                    return (
                      <>
                        <LuHardDrive className={className} />
                        <div
                          className={cx(className, "h-2 w-2 rounded-full bg-blue-700", {
                            hidden: !remoteVirtualMediaState,
                          })}
                        />
                      </>
                    );
                  }}
                  onClick={() => {
                    setDisableVideoFocusTrap(true);
                  }}
                />
              </PopoverButton>
              <PopoverPanel
                anchor="bottom start"
                transition
                className={cx(
                  "z-10 flex w-[420px] origin-top flex-col overflow-visible!",
                  "flex origin-top flex-col transition duration-300 ease-out data-closed:translate-y-8 data-closed:opacity-0",
                )}
              >
                {({ open }) => {
                  checkIfStateChanged(open);
                  return (
                    <div className="mx-auto w-full max-w-xl">
                      <MountPopopover />
                    </div>
                  );
                }}
              </PopoverPanel>
            </Popover>
          </div>
          <div>
            <Popover>
              <PopoverButton as={Fragment}>
                <Button
                  size="XS"
                  theme="light"
                  text="Files"
                  LeadingIcon={LuFolderOpen}
                  onClick={() => setDisableVideoFocusTrap(true)}
                />
              </PopoverButton>
              <PopoverPanel
                anchor="bottom start"
                transition
                className={cx(
                  "z-10 flex w-[420px] origin-top flex-col overflow-visible!",
                  "flex origin-top flex-col transition duration-300 ease-out data-closed:translate-y-8 data-closed:opacity-0",
                )}
              >
                {({ open }) => {
                  checkIfStateChanged(open);
                  return (
                    <div className="mx-auto w-full max-w-xl">
                      <FileTransferPopover />
                    </div>
                  );
                }}
              </PopoverPanel>
            </Popover>
          </div>
          <div>
            <Popover>
              <PopoverButton as={Fragment}>
                <Button
                  size="XS"
                  theme="light"
                  text={m.action_bar_wake_on_lan()}
                  onClick={() => {
                    setDisableVideoFocusTrap(true);
                  }}
                  LeadingIcon={({ className }) => (
                    <svg
                      className={className}
                      xmlns="http://www.w3.org/2000/svg"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    >
                      <path d="m15 20 3-3h2a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h2l3 3z" />
                      <path d="M6 8v1" />
                      <path d="M10 8v1" />
                      <path d="M14 8v1" />
                      <path d="M18 8v1" />
                    </svg>
                  )}
                />
              </PopoverButton>
              <PopoverPanel
                anchor="bottom start"
                transition
                style={{
                  transitionProperty: "opacity",
                }}
                className={cx(
                  "z-10 flex w-[420px] origin-top flex-col overflow-visible!",
                  "flex origin-top flex-col transition duration-300 ease-out data-closed:translate-y-8 data-closed:opacity-0",
                )}
              >
                {({ open }) => {
                  checkIfStateChanged(open);
                  return (
                    <div className="mx-auto w-full max-w-xl">
                      <WakeOnLanModal />
                    </div>
                  );
                }}
              </PopoverPanel>
            </Popover>
          </div>
          <div className="hidden lg:block">
            <Button
              size="XS"
              theme="light"
              text={m.action_bar_virtual_keyboard()}
              LeadingIcon={FaKeyboard}
              onClick={() => setVirtualKeyboardEnabled(!isVirtualKeyboardEnabled)}
            />
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-x-2 gap-y-2">
          <Popover>
            <PopoverButton as={Fragment}>
              <Button
                size="XS"
                theme="light"
                text={m.action_bar_extension()}
                LeadingIcon={LuCable}
                onClick={() => {
                  setDisableVideoFocusTrap(true);
                }}
              />
            </PopoverButton>
            <PopoverPanel
              anchor="bottom start"
              transition
              className={cx(
                "z-10 flex w-[420px] flex-col overflow-visible!",
                "flex origin-top flex-col transition duration-300 ease-out data-closed:translate-y-8 data-closed:opacity-0",
              )}
            >
              {({ open }) => {
                checkIfStateChanged(open);
                return <ExtensionPopover />;
              }}
            </PopoverPanel>
          </Popover>

          <div className="block lg:hidden">
            <Button
              size="XS"
              theme="light"
              text={m.action_bar_virtual_keyboard()}
              LeadingIcon={FaKeyboard}
              onClick={() => setVirtualKeyboardEnabled(!isVirtualKeyboardEnabled)}
            />
          </div>
          <div className="hidden md:block">
            <Button
              size="XS"
              theme="light"
              text={m.action_bar_connection_stats()}
              LeadingIcon={({ className }) => (
                <LuSignal className={cx(className, "mb-0.5 text-green-500")} strokeWidth={4} />
              )}
              onClick={() => {
                toggleSidebarView("connection-stats");
              }}
            />
          </div>
          {audioTransceiver && (
            <div>
              <Button
                size="XS"
                theme={micEnabled ? "primary" : "light"}
                text={micEnabled ? m.action_bar_mic_on() : m.action_bar_mic_off()}
                LeadingIcon={micEnabled ? LuMic : LuMicOff}
                onClick={() => void handleMicToggle()}
              />
            </div>
          )}
          {!isEmbedMode && (
            <div>
              <Button
                size="XS"
                theme="light"
                text={m.action_bar_settings()}
                LeadingIcon={LuSettings}
                onClick={() => {
                  setDisableVideoFocusTrap(true);
                  navigateTo("/settings");
                }}
              />
            </div>
          )}

          <div className="hidden items-center gap-x-2 lg:flex">
            <div className="h-4 w-px bg-slate-300 dark:bg-slate-600" />
            {isEmbedMode ? (
              <Button
                size="XS"
                theme="light"
                text={m.close()}
                LeadingIcon={LuX}
                onClick={() => window.close()}
              />
            ) : (
              <SplitButtonGroup>
                <SplitButtonPrimary
                  icon={LuMaximize}
                  label={m.action_bar_fullscreen()}
                  onClick={() => requestFullscreen()}
                />
                <SplitButtonCaret
                  menuItems={[
                    {
                      label: m.action_bar_compact_window(),
                      icon: LuExternalLink,
                      onClick: () => {
                        const url = new URL(window.location.href);
                        url.searchParams.set("embed", "");
                        window.open(url.toString(), "_blank", "noopener");
                      },
                    },
                  ]}
                />
              </SplitButtonGroup>
            )}
          </div>
        </div>
      </div>
    </Container>
  );
}
