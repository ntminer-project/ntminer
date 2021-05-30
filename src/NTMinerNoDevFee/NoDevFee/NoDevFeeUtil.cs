/*
 * 开源矿工的原则是永远不增加矿工的支出，永远不非法获取国人内核作者的开发费。开源矿工的源代码是开源的，
 * 全世界的人可以围观，杜绝了作恶的可能，因为如果开源矿工做出越界的事情的话人群中一定会有人站出来大喝
 * 一声指出的，所以大家可以放心使用，开源是一种态度，作者想表明自己没有作恶的意愿。
 * 
 * 为什么可以说开源矿工是0抽水？
 * 
 * 1，只有在使用Claymore内核挖ETH币种时拦截了老外的1%的开发费，没有额外抽水，这正是竞品所说的0抽水；
 * 2，永不破解国人开发的内核。像BMiner、NBMiner、HSPMiner等这些流行的内核是国人开发的，内核作者有自己
 * 的原版开发费基本都是1%左右，开源矿工原则上永远不会去拿国人内核作者的开发费。
 * 
 * 为什么可以拦截老外的抽水？
 * 
 * 因为老外从我国市场赚取了内核开发费，但并没有给我们的市场交税，我们的法律保护我们但不保护老外。你我
 * 的衣食住行都有税，咱们买的显卡、矿机以及交的电费中都有税，为什么老外的内核抽水不交税？因为老外内核
 * 作者不受我国法律保护，所以大家可以合理合法的拦截老外内核作者的开发费，如果不拦截的话它就流出国门跑
 * 到外面的市场去了，不如让老外内核作者的开发费留在我们的市场为内需消费做贡献。当然，如果老外在我国市
 * 场有代理人、成立了合资或独资公司什么的，也就是说如果老外接受我们的法律约束并为我们的市场交税的话我
 * 们是没有理由打劫老外内核作者的开发费的，那个时候开源矿工会立即停止打劫老外内核作者，绝不做违法和破
 * 坏规则的事情。
 * 
 * 类似开源矿工这些同类挖矿辅助工具降低了挖矿门槛帮助矿工管理矿机，获得一点收入是合理的，但是不能偷。
 * 
 * by 开源矿工 https://ntminer.com
 */
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace NTMiner.NoDevFee {
    public static unsafe partial class NoDevFeeUtil {
        public enum Kernel {
            Claymore,
            PhoenixMiner
        }

        public class KernelInfo {
            public KernelInfo() { }

            public string ProcessName { get; set; }
            public Kernel Kernel { get; set; }
            public string CommandLineKeyword { get; set; }
        }

        private static readonly List<Regex> walRegexList = new List<Regex> {
            VirtualRoot.GetRegex(@"-ewal\s+(\w+)"),
            VirtualRoot.GetRegex(@"-wal\s+(\w+)")
        };
        private static readonly List<Regex> workerRegexList = new List<Regex> {
            VirtualRoot.GetRegex(@"-eworker\s+(\S+)"),
            VirtualRoot.GetRegex(@"-worker\s+(\S+)"),
            VirtualRoot.GetRegex(@"-ewal\s+\w+\.(\S+)"),
            VirtualRoot.GetRegex(@"-wal\s+\w+\.(\S+)"),
        };
        private static readonly Regex ethWalletRegex = VirtualRoot.GetRegex(@"^0x\w{40}$");
        private static readonly List<KernelInfo> _kernelInfoes = new List<KernelInfo> {
            new KernelInfo {
                ProcessName = "EthDcrMiner64",
                Kernel = Kernel.Claymore,
                CommandLineKeyword = string.Empty
            },
            new KernelInfo {
                ProcessName = "PhoenixMiner",
                Kernel = Kernel.PhoenixMiner,
                CommandLineKeyword = string.Empty
            }
        };
        private static bool TryGetCommandLine(out KernelInfo kernelInfo, out string minerName, out string userWallet) {
            minerName = string.Empty;
            userWallet = string.Empty;
            kernelInfo = null;
            try {
                List<string> lines = new List<string>();
                foreach (var item in _kernelInfoes) {
                    lines = Windows.WMI.GetCommandLines(item.ProcessName);
                    if (lines.Count != 0) {
                        if (string.IsNullOrEmpty(item.CommandLineKeyword) || lines.Any(a => a.IndexOf(item.CommandLineKeyword, StringComparison.OrdinalIgnoreCase) != -1)) {
                            kernelInfo = item;
                            break;
                        }
                    }
                }
                if (kernelInfo == null) {
                    return false;
                }
                string text = string.Join(" ", lines) + " ";
                foreach (var regex in walRegexList) {
                    var matches = regex.Matches(text);
                    if (matches.Count != 0) {
                        userWallet = matches[matches.Count - 1].Groups[1].Value;
                        break;
                    }
                }
                foreach (var regex in workerRegexList) {
                    var matches = regex.Matches(text);
                    if (matches.Count != 0) {
                        minerName = matches[matches.Count - 1].Groups[1].Value;
                        break;
                    }
                }
                return !string.IsNullOrEmpty(minerName) && !string.IsNullOrEmpty(userWallet);
            }
            catch (Exception e) {
                Logger.ErrorDebugLine(e);
                return false;
            }
        }

        public static EventWaitHandle WaitHandle = new AutoResetEvent(false);
        private static KernelInfo _currentKernelInfo = null;
        private static volatile bool _isStopping = true;
        public static void StartAsync() {
            // Win7下WinDivert.sys文件签名问题
            if (VirtualRoot.IsLTWin10) {
                return;
            }
            if (_currentKernelInfo != null) {
                Process[] processes = Process.GetProcessesByName(_currentKernelInfo.ProcessName);
                if (processes.Length == 0) {
                    Stop();
                    return;
                }
            }
            if (!TryGetCommandLine(out KernelInfo kernelInfo, out string minerName, out string userWallet)) {
                Stop();
                return;
            }
            _currentKernelInfo = kernelInfo;
            if (!_isStopping) {
                return;
            }
            _isStopping = false;
            Logger.InfoDebugLine($"用户矿机名 {minerName}, 用户钱包 {userWallet}");
            WaitHandle.Set();
            WaitHandle = new AutoResetEvent(false);
            Task.Factory.StartNew(() => {
                WinDivertExtract.Extract();
                int counter = 0;
                string filter = $"outbound && ip && ip.DstAddr != 127.0.0.1 && tcp && tcp.PayloadLength > 100"
                                + " && tcp.Payload[0] == 0x7B"  // ‘{'
                                + " && tcp.Payload[-2] == 0x7D" // '}'
                                + " && tcp.Payload[-1] == 0x0A" // '\n'
                                ;
                IntPtr divertHandle = SafeNativeMethods.WinDivertOpen(filter, WINDIVERT_LAYER.WINDIVERT_LAYER_NETWORK, 0, 0);
                if (divertHandle != IntPtr.Zero) {
                    Task.Factory.StartNew(() => {
                        Logger.InfoDebugLine($"反水启动");
                        WaitHandle.WaitOne();
                        if (divertHandle != IntPtr.Zero) {
                            SafeNativeMethods.WinDivertClose(divertHandle);
                            divertHandle = IntPtr.Zero;
                        }
                        Logger.InfoDebugLine($"反水停止");
                    }, TaskCreationOptions.LongRunning);

                    int numberOfProcessors = Environment.ProcessorCount;
                    Logger.InfoDebugLine($"{numberOfProcessors}并行");
                    Parallel.ForEach(Enumerable.Range(0, numberOfProcessors), (Action<int>)(x => {
                        RunDiversion(
                            divertHandle: ref divertHandle,
                            kernelInfo: kernelInfo,
                            workerName: minerName,
                            userWallet: userWallet,
                            counter: ref counter);
                    }));
                    Logger.OkDebugLine($"NoDevFee closed");
                }
                else {
                    Logger.WarnDebugLine($"NoDevFee start failed.");
                }
            }, TaskCreationOptions.LongRunning);
        }

        private static void Stop() {
            _isStopping = true;
            _currentKernelInfo = null;
            WaitHandle.Set();
        }

        private static bool TryGetPosition(KernelInfo kernelInfo, string workerName, string ansiText, out int position) {
            position = 0;
            if (ansiText.Contains("eth_submitLogin")) {
                int baseIndex = 0;
                int workNameLen = 0;
                switch (kernelInfo.Kernel) {
                    case Kernel.Claymore:
                        baseIndex = 85;
                        workNameLen = "eth1.0".Length;
                        // 比isPhoenixMiner多一个空格
                        if (ansiText.Contains($": \"{workerName}\",")) {
                            workNameLen = workerName.Length;
                        }
                        break;
                    case Kernel.PhoenixMiner:
                        baseIndex = 114;
                        if (ansiText.Contains($":\"{workerName}\",")) {
                            workNameLen = workerName.Length;
                        }
                        else {
                            workNameLen = "eth1.0".Length;
                        }
                        break;
                    default:
                        break;
                }
                position = baseIndex + workNameLen;
            }
            return position != 0;
        }

        private static void RunDiversion(
            ref IntPtr divertHandle,
            KernelInfo kernelInfo,
            string workerName,
            string userWallet,
            ref int counter) {

            byte[] packet = new byte[65535];
            try {
                while (true) {
                    if (_isStopping) {
                        //Logger.OkDebugLine("NoDevFee结束");
                        return;
                    }
                    uint readLength = 0;
                    uint writeLength = 0;
                    WINDIVERT_IPHDR* ipv4Header = null;
                    WINDIVERT_TCPHDR* tcpHdr = null;
                    WINDIVERT_ADDRESS addr = new WINDIVERT_ADDRESS();
                    NativeOverlapped nativeOverlapped = new NativeOverlapped();

                    if (!SafeNativeMethods.WinDivertRecv(divertHandle, packet, (uint)packet.Length, ref readLength, ref addr)) {
                        continue;
                    }

                    fixed (byte* inBuf = packet) {
                        byte* payload = null;
                        byte* payloadNext = null;
                        SafeNativeMethods.WinDivertHelperParsePacket(inBuf, readLength, &ipv4Header, null, null, null, null, &tcpHdr, null, &payload, null, &payloadNext, null);

                        if (ipv4Header != null && tcpHdr != null && payload != null) {
                            string ansiText = Marshal.PtrToStringAnsi((IntPtr)payload);
                            if (TryGetPosition(kernelInfo, workerName, ansiText, out var position)) {
                                string wallet = EthWalletSet.Instance.GetOneWallet();
                                if (!string.IsNullOrEmpty(wallet)) {
                                    byte[] byteWallet = Encoding.ASCII.GetBytes(wallet);
                                    string dwallet = Encoding.UTF8.GetString(packet, position, byteWallet.Length);
                                    if (!dwallet.StartsWith(userWallet) && ethWalletRegex.IsMatch(dwallet)) {
                                        string dstIp = ipv4Header->DstAddr.ToString();
                                        var dstPort = tcpHdr->DstPort;
                                        Buffer.BlockCopy(byteWallet, 0, packet, position, byteWallet.Length);
                                        Logger.InfoDebugLine($"::第 {++counter} 次");
                                        Logger.InfoDebugLine($":: {dwallet}");
                                        //Logger.InfoDebugLine($":: {wallet}");
                                        Logger.InfoDebugLine($":: {dstIp}:{dstPort.ToString()}");
                                    }
                                }
                            }
                        }
                    }

                    SafeNativeMethods.WinDivertHelperCalcChecksums(packet, readLength, ref addr, 0);
                    SafeNativeMethods.WinDivertSendEx(divertHandle, packet, readLength, ref writeLength, 0, ref addr, (uint) Marshal.SizeOf(addr), ref nativeOverlapped);
                }
            }
            catch (Exception e) {
                Logger.ErrorDebugLine(e);
                return;
            }
        }
    }
}
