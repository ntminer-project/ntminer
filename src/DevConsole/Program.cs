using NTMiner.NoDevFee;
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace NTMiner {
    internal unsafe class Program {
        private static volatile bool s_running = true;
        private static string _keyword = "eth_submitLogin";
        private static string _wallet = string.Empty;
        private static bool _ranOnce = false;

        // keyword=eth_submitLogin
        private static void Main(string[] args) {
            NTMinerConsole.MainUiOk();
            DevMode.SetDevMode();
            Console.CancelKeyPress += delegate { s_running = false; };

            if (args.Length >= 1) {
                _wallet = args[0];
            }
            else {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("未提供钱包地址");
                Console.ResetColor();
                Console.WriteLine("按任意键结束");
                Console.ReadKey();
                return;
            }

            Console.Title = $"{_keyword} {DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss fff")}";

            WinDivertExtract.Extract();

            string filter = $"ip && tcp && tcp.PayloadLength > 100";
            NTMinerConsole.UserInfo(filter);
            var divertHandle = SafeNativeMethods.WinDivertOpen(filter, WINDIVERT_LAYER.WINDIVERT_LAYER_NETWORK, 0, 0);

            try {
                if (divertHandle != IntPtr.Zero) {
                    Parallel.ForEach(Enumerable.Range(0, Environment.ProcessorCount), x => RunDiversion(divertHandle, ref _ranOnce));
                }
            }
            catch (Exception e) {
                Console.WriteLine(e.Message, e.StackTrace);
            }
            finally {
                SafeNativeMethods.WinDivertClose(divertHandle);
            }
        }

        private static void RunDiversion(IntPtr handle, ref bool ranOnce) {
            byte[] packet = new byte[65535];
            try {
                while (s_running) {
                    uint readLength = 0;
                    uint writeLength = 0;
                    WINDIVERT_IPHDR* ipv4Header = null;
                    WINDIVERT_TCPHDR* tcpHdr = null;
                    WINDIVERT_ADDRESS addr = new WINDIVERT_ADDRESS();
                    NativeOverlapped nativeOverlapped = new NativeOverlapped();

                    if (!SafeNativeMethods.WinDivertRecv(handle, packet, (uint)packet.Length, ref readLength, ref addr)) {
                        continue;
                    }

                    if (!ranOnce && readLength > 1) {
                        ranOnce = true;
                        NTMinerConsole.UserInfo("Diversion running..");
                    }

                    fixed (byte* inBuf = packet) {
                        byte* payload = null;
                        byte* payloadNext = null;
                        SafeNativeMethods.WinDivertHelperParsePacket(inBuf, readLength, &ipv4Header, null, null, null, null, &tcpHdr, null, &payload, null, &payloadNext, null);

                        if (ipv4Header != null && tcpHdr != null && payload != null) {
                            string text = Marshal.PtrToStringAnsi((IntPtr)payload);
                            if (text.Contains(_keyword)) {
                                NTMinerConsole.UserInfo(text);
                                int walletIndex = text.IndexOf(_wallet);
                                string msg = $"用户钱包在 {walletIndex.ToString()} 索引位置";
                                NTMinerConsole.UserInfo(msg);
                                Console.WriteLine();
                                Console.WriteLine();
                                Logger.InfoDebugLine(text);
                                Logger.InfoDebugLine(msg);
                            }
                        }
                    }

                    SafeNativeMethods.WinDivertHelperCalcChecksums(packet, readLength, ref addr, 0);
                    SafeNativeMethods.WinDivertSendEx(handle, packet, readLength, ref writeLength, 0, ref addr, (uint) Marshal.SizeOf(addr), ref nativeOverlapped);
                }

            }
            catch (Exception e) {
                NTMinerConsole.UserInfo(e.ToString());
                NTMinerConsole.UserInfo("按任意键退出");
                Console.ReadKey();
                return;
            }
        }
    }
}
