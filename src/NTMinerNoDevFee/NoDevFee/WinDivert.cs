/*
 * https://github.com/basil00/Divert/blob/master/include/windivert.h
 */

using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;

namespace NTMiner.NoDevFee {
//     internal class WinDivertConstants {
//         /// WINDIVERT_DIRECTION_OUTBOUND -> 0
//         public const int WINDIVERT_DIRECTION_OUTBOUND = 0;

//         /// WINDIVERT_DIRECTION_INBOUND -> 1
//         public const int WINDIVERT_DIRECTION_INBOUND = 1;

//         /// WINDIVERT_FLAG_SNIFF -> 1
//         public const int WINDIVERT_FLAG_SNIFF = 1;

//         /// WINDIVERT_FLAG_DROP -> 2
//         public const int WINDIVERT_FLAG_DROP = 2;

//         /// WINDIVERT_PARAM_MAX -> WINDIVERT_PARAM_QUEUE_TIME
//         public const WINDIVERT_PARAM WINDIVERT_PARAM_MAX = WINDIVERT_PARAM.WINDIVERT_PARAM_QUEUE_TIME;
//     }

    internal class WinDivertHelpers {
        public static ushort SwapOrder(ushort val) {
            return (ushort)(((val & 0xFF00) >> 8) | ((val & 0x00FF) << 8));
        }

        public static uint SwapOrder(uint val) {
            val = (val >> 16) | (val << 16);
            return ((val & 0xFF00) >> 8) | ((val & 0x00FF) << 8);
        }

        public static ulong SwapOrder(ulong val) {
            val = (val >> 32) | (val << 32);
            val = ((val & 0xFFFF0000FFFF0000) >> 16) | ((val & 0x0000FFFF0000FFFF) << 16);
            return ((val & 0xFF00FF00FF00FF00) >> 8) | ((val & 0x00FF00FF00FF00FF) << 8);
        }

        /// <summary>
        /// Gets the fragment offset for the given ipv4 header.
        /// </summary>
        /// <param name="hdr">
        /// The ipv4 header.
        /// </param>
        /// <returns>
        /// The extracted fragment offset from the given ipv4 header.
        /// </returns>
        public static ushort WINDIVERT_IPHDR_GET_FRAGOFF(WINDIVERT_IPHDR hdr) {
            return (ushort)((hdr.FragOff0) & 0xFF1F);
        }

        /// <summary>
        /// Gets whether or not given ipv4 header has the more fragments flag set.
        /// </summary>
        /// <param name="hdr">
        /// The ipv4 header.
        /// </param>
        /// <returns>
        /// True if the given ipv4 has the more fragments flag set, false otherwise.
        /// </returns>
        public static bool WINDIVERT_IPHDR_GET_MF(WINDIVERT_IPHDR hdr) {
            return (ushort)((hdr.FragOff0) & 0x0020) != 0;
        }

        /// <summary>
        /// Gets whether or not given ipv4 header has the don't fragment flag set.
        /// </summary>
        /// <param name="hdr">
        /// The ipv4 header.
        /// </param>
        /// <returns>
        /// True if the given ipv4 has the don't fragment flag set, false otherwise.
        /// </returns>
        public static bool WINDIVERT_IPHDR_GET_DF(WINDIVERT_IPHDR hdr) {
            return (ushort)((hdr.FragOff0) & 0x0040) != 0;
        }

        /// <summary>
        /// Gets whether or not given ipv4 header has the reserved flag set.
        /// </summary>
        /// <param name="hdr">
        /// The ipv4 header.
        /// </param>
        /// <returns>
        /// True if the given ipv4 has the reserved flag set, false otherwise.
        /// </returns>
        public static bool WINDIVERT_IPHDR_GET_RESERVED(WINDIVERT_IPHDR hdr) {
            return (ushort)((hdr.FragOff0) & 0x0080) != 0;
        }

        /// <summary>
        /// Sets the fragment offset for the given ipv4 header.
        /// </summary>
        /// <param name="header">
        /// The ipv4 header.
        /// </param>
        /// <param name="val">
        /// The fragment offset.
        /// </param>
        public static void WINDIVERT_IPHDR_SET_FRAGOFF(WINDIVERT_IPHDR header, ushort val) {
            header.FragOff0 = (ushort)(((header.FragOff0) & 0x00E0) | ((val) & 0xFF1F));
        }

        /// <summary>
        /// Sets the more fragments flag to the given value.
        /// </summary>
        /// <param name="header">
        /// The ipv4 header.
        /// </param>
        /// <param name="val">
        /// The more fragments flag value.
        /// </param>
        public static void WINDIVERT_IPHDR_SET_MF(WINDIVERT_IPHDR header, ushort val) {
            header.FragOff0 = (ushort)(((header.FragOff0) & 0xFFDF) | (((val) & 0x0001) << 5));
        }

        /// <summary>
        /// Sets the don't fragment flag to the given value.
        /// </summary>
        /// <param name="header">
        /// The ipv4 header.
        /// </param>
        /// <param name="val">
        /// The don't fragment flag value.
        /// </param>
        public static void WINDIVERT_IPHDR_SET_DF(WINDIVERT_IPHDR header, ushort val) {
            header.FragOff0 = (ushort)(((header.FragOff0) & 0xFFBF) | (((val) & 0x0001) << 6));
        }

        /// <summary>
        /// Sets the reserved flag to the given value.
        /// </summary>
        /// <param name="header">
        /// The ipv4 header.
        /// </param>
        /// <param name="val">
        /// The reserved flag value.
        /// </param>
        public static void WINDIVERT_IPHDR_SET_RESERVED(WINDIVERT_IPHDR header, ushort val) {
            header.FragOff0 = (ushort)(((header.FragOff0) & 0xFF7F) | (((val) & 0x0001) << 7));
        }

        /// <summary>
        /// Gets the traffic class value.
        /// </summary>
        /// <param name="hdr">
        /// The ipv6 header.
        /// </param>
        /// <returns>
        /// The traffic class value.
        /// </returns>
        public static uint WINDIVERT_IPV6HDR_GET_TRAFFICCLASS(WINDIVERT_IPV6HDR hdr) {
            return (byte)((hdr.TrafficClass0 << 4) | (byte)hdr.TrafficClass1);
        }

        /// <summary>
        /// Gets the flow label value.
        /// </summary>
        /// <param name="hdr">
        /// The ipv6 header.
        /// </param>
        /// <returns>
        /// The flow label value.
        /// </returns>
        public static uint WINDIVERT_IPV6HDR_GET_FLOWLABEL(WINDIVERT_IPV6HDR hdr) {
            return (uint)((hdr.FlowLabel0 << 16) | hdr.FlowLabel1);
        }

        /// <summary>
        /// Sets the traffic class value.
        /// </summary>
        /// <param name="hdr">
        /// The ipv6 header.
        /// </param>
        /// <param name="val">
        /// The value.
        /// </param>
        public static void WINDIVERT_IPV6HDR_SET_TRAFFICCLASS(WINDIVERT_IPV6HDR hdr, byte val) {
            hdr.TrafficClass0 = (byte)((val) >> 4);
            hdr.TrafficClass1 = val;
        }

#pragma warning disable IDE0060 // 删除未使用的参数
        /// <summary>
        /// Sets the flow label value.
        /// </summary>
        /// <param name="hdr">
        /// The ipv6 header.
        /// </param>
        /// <param name="val">
        /// The value.
        /// </param>
        public static void WINDIVERT_IPV6HDR_SET_FLOWLABEL(WINDIVERT_IPV6HDR hdr, uint val) {
#pragma warning restore IDE0060 // 删除未使用的参数
            //hdr.FlowLabel0 = (uint)(val >> 16);
            //hdr.FlowLabel1 = (ushort)val;
        }

//         /// WINDIVERT_HELPER_NO_IP_CHECKSUM -> 1
//         public const int WINDIVERT_HELPER_NO_IP_CHECKSUM = 1;

//         /// WINDIVERT_HELPER_NO_ICMP_CHECKSUM -> 2
//         public const int WINDIVERT_HELPER_NO_ICMP_CHECKSUM = 2;

//         /// WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM -> 4
//         public const int WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM = 4;

//         /// WINDIVERT_HELPER_NO_TCP_CHECKSUM -> 8
//         public const int WINDIVERT_HELPER_NO_TCP_CHECKSUM = 8;

//         /// WINDIVERT_HELPER_NO_UDP_CHECKSUM -> 16
//         public const int WINDIVERT_HELPER_NO_UDP_CHECKSUM = 16;

//         /// WINDIVERT_HELPER_NO_REPLACE -> 2048
//         public const int WINDIVERT_HELPER_NO_REPLACE = 2048;
    }

    internal enum WinDivertPacketFlags : byte
    {
        Sniffed = 1 << 0,
        Outbound = 1 << 1,
        Loopback = 1 << 2,
        Impostor = 1 << 3,
        IPv6 = 1 << 4,
        IPChecksum = 1 << 5,
        TCPChecksum = 1 << 6,
        UDPChecksum = 1 << 7,
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct WINDIVERT_ADDRESS {
        /// INT64
        public long Timestamp;
        /// UINT32:8
        public byte Layer;

        /// UINT32:8
        public byte Event;
        ///
        public WinDivertPacketFlags Flags;

        /// UINT32:8
        public byte Reserved1;
        /// UINT32
        public uint Reserved2;
        public fixed byte Reserved3[64];
    }

    internal enum WINDIVERT_LAYER {
        /// WINDIVERT_LAYER_NETWORK -> 0
        WINDIVERT_LAYER_NETWORK = 0,

        /// WINDIVERT_LAYER_NETWORK_FORWARD -> 1
        WINDIVERT_LAYER_NETWORK_FORWARD = 1,

        /// WINDIVERT_LAYER_FLOW -> 2
        WINDIVERT_LAYER_FLOW = 2,

        /// WINDIVERT_LAYER_SOCKET -> 3
        WINDIVERT_LAYER_SOCKET = 3,

        /// WINDIVERT_LAYER_REFLECT -> 4
        WINDIVERT_LAYER_REFLECT = 4,
    }

//     internal enum WINDIVERT_PARAM {
//         /// WINDIVERT_PARAM_QUEUE_LEN -> 0
//         WINDIVERT_PARAM_QUEUE_LEN = 0,

//         /// WINDIVERT_PARAM_QUEUE_TIME -> 1
//         WINDIVERT_PARAM_QUEUE_TIME = 1,
//     }

    internal struct WINDIVERT_IPHDR {
        public uint HdrLength {
            get {
                return ((uint)((this.bitvector1 & 15u)));
            }
            set {
                this.bitvector1 = ((byte)((value | this.bitvector1)));
            }
        }

        public uint Version {
            get {
                return ((uint)(((this.bitvector1 & 240u)
                            / 16)));
            }
            set {
                this.bitvector1 = ((byte)(((value * 16)
                            | this.bitvector1)));
            }
        }

        /// HdrLength : 4
        ///Version : 4
        private byte bitvector1;

#pragma warning disable CS0649 // 赋值，字段将一直保持默认值
        /// UINT8->unsigned char
        public byte TOS;

        /// UINT16->unsigned short
        public ushort Length;

        /// UINT16->unsigned short
        public ushort FragOff0;

        /// UINT8->unsigned char
        public byte TTL;

        /// UINT8->unsigned char
        public byte Protocol;
        /// UINT16->unsigned short
        public ushort Id;

        /// UINT16->unsigned short
        public ushort Checksum;
#pragma warning restore CS0649 // 对同一变量进行了比较

        /// UINT32->unsigned int
        public IPAddress SrcAddr {
            get {
                return new IPAddress(unchecked((long)this.SourceAddress));
            }

            set {
                Debug.Assert(value.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork, "Not a valid IPV4 address.");

                if (value.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) {
                    throw new ArgumentException("Not a valid IPV4 address.", nameof(SrcAddr));
                }

                this.SourceAddress = (uint)BitConverter.ToInt32(value.GetAddressBytes(), 0);
            }
        }

        private uint SourceAddress;

        /// UINT32->unsigned int
        public IPAddress DstAddr {
            get {
                return new IPAddress(unchecked((long)this.DestinationAddress));
            }

            set {
                Debug.Assert(value.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork, "Not a valid IPV4 address.");

                if (value.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) {
                    throw new ArgumentException("Not a valid IPV4 address.", nameof(DstAddr));
                }

                this.DestinationAddress = (uint)BitConverter.ToInt32(value.GetAddressBytes(), 0);
            }
        }

        private uint DestinationAddress;
    }

    internal unsafe struct WINDIVERT_IPV6HDR {
        public uint TrafficClass0 {
            get {
                return ((uint)((this.bitvector1 & 15u)));
            }
            set {
                this.bitvector1 = ((ushort)((value | this.bitvector1)));
            }
        }

        public uint Version {
            get {
                return ((uint)(((this.bitvector1 & 240u)
                            / 16)));
            }
            set {
                this.bitvector1 = ((ushort)(((value * 16)
                            | this.bitvector1)));
            }
        }

        public uint FlowLabel0 {
            get {
                return ((uint)(((this.bitvector1 & 3840u)
                            / 256)));
            }
            set {
                this.bitvector1 = ((ushort)(((value * 256)
                            | this.bitvector1)));
            }
        }

        public uint TrafficClass1 {
            get {
                return ((uint)(((this.bitvector1 & 61440u)
                            / 4096)));
            }
            set {
                this.bitvector1 = ((ushort)(((value * 4096)
                            | this.bitvector1)));
            }
        }

#pragma warning disable CS0649 // 赋值，字段将一直保持默认值
        /// TrafficClass0 : 4
        ///Version : 4
        ///FlowLabel0 : 4
        ///TrafficClass1 : 4
        private ushort bitvector1;

        /// UINT16->unsigned short
        public ushort FlowLabel1;

        /// UINT16->unsigned short
        public ushort Length;

        /// UINT8->unsigned char
        public byte NextHdr;

        /// UINT8->unsigned char
        public byte HopLimit;
#pragma warning restore CS0649 // 对同一变量进行了比较

        /// UINT32[4]
        public IPAddress SrcAddr {
            get {
                fixed (uint* addr = this.SourceAddress) {
                    var b1 = BitConverter.GetBytes(addr[0]);
                    var b2 = BitConverter.GetBytes(addr[1]);
                    var b3 = BitConverter.GetBytes(addr[2]);
                    var b4 = BitConverter.GetBytes(addr[3]);
                    var bytes = new byte[] {
                        b1[0], b1[1], b1[2], b1[3],
                        b2[0], b2[1], b2[2], b2[3],
                        b3[0], b3[1], b3[2], b3[3],
                        b4[0], b4[1], b4[2], b4[3]
                    };

                    return new IPAddress(bytes);
                }
            }

            set {
                fixed (uint* addr = this.SourceAddress) {
                    var valueBytes = value.GetAddressBytes();

                    Debug.Assert(valueBytes.Length == 16, "Not a valid IPV6 address.");

                    if (valueBytes.Length != 16) {
                        throw new ArgumentException("Not a valid IPV6 address.", nameof(SrcAddr));
                    }

                    addr[0] = BitConverter.ToUInt32(valueBytes, 0);
                    addr[1] = BitConverter.ToUInt32(valueBytes, 4);
                    addr[2] = BitConverter.ToUInt32(valueBytes, 8);
                    addr[3] = BitConverter.ToUInt32(valueBytes, 12);
                }
            }
        }

        private fixed uint SourceAddress[4];

        /// UINT32[4]
        public IPAddress DstAddr {
            get {
                fixed (uint* addr = this.DestinationAddress) {
                    var b1 = BitConverter.GetBytes(addr[0]);
                    var b2 = BitConverter.GetBytes(addr[1]);
                    var b3 = BitConverter.GetBytes(addr[2]);
                    var b4 = BitConverter.GetBytes(addr[3]);
                    var bytes = new byte[] {
                    b1[0], b1[1], b1[2], b1[3],
                    b2[0], b2[1], b2[2], b2[3],
                    b3[0], b3[1], b3[2], b3[3],
                    b4[0], b4[1], b4[2], b4[3]
                };
                    return new IPAddress(bytes);
                }
            }

            set {
                fixed (uint* addr = this.DestinationAddress) {
                    var valueBytes = value.GetAddressBytes();

                    Debug.Assert(valueBytes.Length == 16, "Not a valid IPV6 address.");

                    if (valueBytes.Length != 16) {
                        throw new ArgumentException("Not a valid IPV6 address.", nameof(DstAddr));
                    }

                    addr[0] = BitConverter.ToUInt32(valueBytes, 0);
                    addr[1] = BitConverter.ToUInt32(valueBytes, 4);
                    addr[2] = BitConverter.ToUInt32(valueBytes, 8);
                    addr[3] = BitConverter.ToUInt32(valueBytes, 12);
                }
            }
        }

        private fixed uint DestinationAddress[4];
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WINDIVERT_ICMPHDR {
        /// UINT8->unsigned char
        public byte Type;

        /// UINT8->unsigned char
        public byte Code;

        /// UINT16->unsigned short
        public ushort Checksum;

        /// UINT32->unsigned int
        public uint Body;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WINDIVERT_ICMPV6HDR {
        /// UINT8->unsigned char
        public byte Type;

        /// UINT8->unsigned char
        public byte Code;

        /// UINT16->unsigned short
        public ushort Checksum;

        /// UINT32->unsigned int
        public uint Body;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WINDIVERT_TCPHDR {
        /// UINT16->unsigned short
        public ushort SrcPort {
            get {
                return WinDivertHelpers.SwapOrder(this.SourcePort);
            }

            set {
                this.SourcePort = WinDivertHelpers.SwapOrder(value);
            }
        }

        /// UINT16->unsigned short
        public ushort DstPort {
            get {
                return WinDivertHelpers.SwapOrder(this.DestinationPort);
            }

            set {
                this.DestinationPort = WinDivertHelpers.SwapOrder(value);
            }
        }

        /// UINT16->unsigned short
        private ushort SourcePort;

        /// UINT16->unsigned short
        private ushort DestinationPort;

        /// UINT32->unsigned int
        public uint SeqNum;

        /// UINT32->unsigned int
        public uint AckNum;

        /// Reserved1 : 4
        ///HdrLength : 4
        ///Fin : 1
        ///Syn : 1
        ///Rst : 1
        ///Psh : 1
        ///Ack : 1
        ///Urg : 1
        ///Reserved2 : 2
        private ushort bitvector1;

        /// UINT16->unsigned short
        public ushort Window;

        /// UINT16->unsigned short
        public ushort Checksum;

        /// UINT16->unsigned short
        public ushort UrgPtr;

        public uint Reserved1 {
            get {
                return ((uint)((this.bitvector1 & 15u)));
            }
            set {
                this.bitvector1 = ((ushort)((value | this.bitvector1)));
            }
        }

        public uint HdrLength {
            get {
                return ((uint)(((this.bitvector1 & 240u)
                            / 16)));
            }
            set {
                this.bitvector1 = ((ushort)(((value * 16)
                            | this.bitvector1)));
            }
        }

        public uint Fin {
            get {
                return ((uint)(((this.bitvector1 & 256u)
                            / 256)));
            }
            set {
                this.bitvector1 = ((ushort)(((value * 256)
                            | this.bitvector1)));
            }
        }

        public uint Syn {
            get {
                return ((uint)(((this.bitvector1 & 512u)
                            / 512)));
            }
            set {
                this.bitvector1 = ((ushort)(((value * 512)
                            | this.bitvector1)));
            }
        }

        public uint Rst {
            get {
                return ((uint)(((this.bitvector1 & 1024u)
                            / 1024)));
            }
            set {
                this.bitvector1 = ((ushort)(((value * 1024)
                            | this.bitvector1)));
            }
        }

        public uint Psh {
            get {
                return ((uint)(((this.bitvector1 & 2048u)
                            / 2048)));
            }
            set {
                this.bitvector1 = ((ushort)(((value * 2048)
                            | this.bitvector1)));
            }
        }

        public uint Ack {
            get {
                return ((uint)(((this.bitvector1 & 4096u)
                            / 4096)));
            }
            set {
                this.bitvector1 = ((ushort)(((value * 4096)
                            | this.bitvector1)));
            }
        }

        public uint Urg {
            get {
                return ((uint)(((this.bitvector1 & 8192u)
                            / 8192)));
            }
            set {
                this.bitvector1 = ((ushort)(((value * 8192)
                            | this.bitvector1)));
            }
        }

        public uint Reserved2 {
            get {
                return ((uint)(((this.bitvector1 & 49152u)
                            / 16384)));
            }
            set {
                this.bitvector1 = ((ushort)(((value * 16384)
                            | this.bitvector1)));
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WINDIVERT_UDPHDR {
        public ushort SrcPort {
            get {
                return WinDivertHelpers.SwapOrder(this.SourcePort);
            }

            set {
                this.SourcePort = WinDivertHelpers.SwapOrder(value);
            }
        }

        /// UINT16->unsigned short
        public ushort DstPort {
            get {
                return WinDivertHelpers.SwapOrder(this.DestinationPort);
            }

            set {
                this.DestinationPort = WinDivertHelpers.SwapOrder(value);
            }
        }

        /// UINT16->unsigned short
        private ushort SourcePort;

        /// UINT16->unsigned short
        public ushort DestinationPort;

        /// UINT16->unsigned short
        public ushort Length;

        /// UINT16->unsigned short
        public ushort Checksum;
    }

    internal class SafeNativeMethods {
        private const string dllPath = "WinDivert.dll";
        /// Return Type: HANDLE->void*
        ///filter: char*
        ///layer: WINDIVERT_LAYER->Anonymous_d7dac89f_91f7_4aca_b997_239f157c8039
        ///priority: INT16->short
        ///flags: UINT64->unsigned __int64
        [DllImport(dllPath, EntryPoint = "WinDivertOpen", SetLastError = true)]
        public static extern IntPtr WinDivertOpen([In] [MarshalAs(UnmanagedType.LPStr)] string filter, WINDIVERT_LAYER layer, short priority, ulong flags);

        /// Return Type: BOOL->int
        ///handle: HANDLE->void*
        ///pPacket: PVOID->void*
        ///packetLen: UINT->unsigned int
        ///pRecvLen: UINT*
        ///pAddr: PWINDIVERT_ADDRESS->Anonymous_7d42ad21_898e_4fdf_a30d_dc1e2c77a38f*
        [DllImport(dllPath, EntryPoint = "WinDivertRecv", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WinDivertRecv([In] IntPtr handle, byte[] pPacket, uint packetLen, ref uint pRecvLen, ref WINDIVERT_ADDRESS pAddr);

//         /// Return Type: BOOL->int
//         ///handle: HANDLE->void*
//         ///pPacket: PVOID->void*
//         ///packetLen: UINT->unsigned int
//         ///flags: UINT64->unsigned __int64
//         ///pAddr: PWINDIVERT_ADDRESS->Anonymous_7d42ad21_898e_4fdf_a30d_dc1e2c77a38f*
//         ///readLen: UINT*
//         ///lpOverlapped: LPOVERLAPPED->_OVERLAPPED*
//         [DllImport(dllPath, EntryPoint = "WinDivertRecvEx", SetLastError = true)]
//         [return: MarshalAs(UnmanagedType.Bool)]
//         public static extern bool WinDivertRecvEx([In] IntPtr handle, byte[] pPacket, uint packetLen, ulong flags, ref WINDIVERT_ADDRESS pAddr, ref uint readLen, ref NativeOverlapped lpOverlapped);

//         /// Return Type: BOOL->int
//         ///handle: HANDLE->void*
//         ///pPacket: PVOID->void*
//         ///packetLen: UINT->unsigned int
//         ///pAddr: PWINDIVERT_ADDRESS->Anonymous_7d42ad21_898e_4fdf_a30d_dc1e2c77a38f*
//         ///writeLen: UINT*
//         [DllImport(dllPath, EntryPoint = "WinDivertSend", SetLastError = true)]
//         [return: MarshalAs(UnmanagedType.Bool)]
//         public static extern bool WinDivertSend([In] IntPtr handle, [In] byte[] pPacket, uint packetLen, [In] ref WINDIVERT_ADDRESS pAddr, ref uint writeLen);

        /// Return Type: BOOL->int
        ///handle: HANDLE->void*
        ///pPacket: PVOID->void*
        ///packetLen: UINT->unsigned int
        ///pSendLen: PUINT
        ///flags: UINT64->unsigned __int64
        ///pAddr: PWINDIVERT_ADDRESS->Anonymous_7d42ad21_898e_4fdf_a30d_dc1e2c77a38f*
        ///addrLen: UINT
        ///lpOverlapped: LPOVERLAPPED->_OVERLAPPED*
        [DllImport(dllPath, EntryPoint = "WinDivertSendEx", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WinDivertSendEx([In] IntPtr handle, [In] byte[] pPacket, uint packetLen, ref uint pSendLen, ulong flags, [In] ref WINDIVERT_ADDRESS pAddr, uint addrLen, ref NativeOverlapped lpOverlapped);

        // [DllImport(dllPath, EntryPoint = "WinDivertSendEx", SetLastError = true)]
        // [return: MarshalAs(UnmanagedType.Bool)]
        // public static extern bool WinDivertSendEx([In] IntPtr handle, [In] byte[] pPacket, uint packetLen, ref uint pSendLen, ulong flags, [In] ref WINDIVERT_ADDRESS pAddr, uint addrLen, IntPtr lpOverlapped);

        /// Return Type: BOOL->int
        ///handle: HANDLE->void*
        [DllImport(dllPath, EntryPoint = "WinDivertClose", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WinDivertClose([In] IntPtr handle);

//         /// Return Type: BOOL->int
//         ///handle: HANDLE->void*
//         ///param: WINDIVERT_PARAM->Anonymous_e5050871_9359_4204_b35d_ed31a2bded35
//         ///value: UINT64->unsigned __int64
//         [DllImport(dllPath, EntryPoint = "WinDivertSetParam", SetLastError = true)]
//         [return: MarshalAs(UnmanagedType.Bool)]
//         public static extern bool WinDivertSetParam([In] IntPtr handle, WINDIVERT_PARAM param, ulong value);

//         /// Return Type: BOOL->int
//         ///handle: HANDLE->void*
//         ///param: WINDIVERT_PARAM->Anonymous_e5050871_9359_4204_b35d_ed31a2bded35
//         ///pValue: UINT64*
//         [DllImport(dllPath, EntryPoint = "WinDivertGetParam", SetLastError = true)]
//         [return: MarshalAs(UnmanagedType.Bool)]
//         public static extern bool WinDivertGetParam([In] IntPtr handle, WINDIVERT_PARAM param, [Out] out ulong pValue);

        /// Return Type: BOOL->int
        ///pPacket: PVOID->void*
        ///packetLen: UINT->unsigned int
        ///ppIpHdr: PWINDIVERT_IPHDR*
        ///ppIpv6Hdr: PWINDIVERT_IPV6HDR*
        ///pProtocol: UINT8 *
        ///ppIcmpHdr: PWINDIVERT_ICMPHDR*
        ///ppIcmpv6Hdr: PWINDIVERT_ICMPV6HDR*
        ///ppTcpHdr: PWINDIVERT_TCPHDR*
        ///ppUdpHdr: PWINDIVERT_UDPHDR*
        ///ppData: PVOID*
        ///pDataLen: UINT*
        ///ppNext: PVOID*
        ///pNextLen: UINT*
        [DllImport(dllPath, EntryPoint = "WinDivertHelperParsePacket", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static unsafe extern bool WinDivertHelperParsePacket(byte* pPacket, uint packetLen, WINDIVERT_IPHDR** ppIpHdr, WINDIVERT_IPV6HDR** ppIpv6Hdr, byte* pProtocol, WINDIVERT_ICMPHDR** ppIcmpHdr, WINDIVERT_ICMPV6HDR** ppIcmpv6Hdr, WINDIVERT_TCPHDR** ppTcpHdr, WINDIVERT_UDPHDR** ppUdpHdr, byte** ppData, uint* pDataLen, byte** ppNext, uint* pNextLen);

//         /// Return Type: BOOL->int
//         ///addrStr: char*
//         ///pAddr: UINT32*
//         [DllImport(dllPath, EntryPoint = "WinDivertHelperParseIPv4Address", SetLastError = true)]
//         [return: MarshalAs(UnmanagedType.Bool)]
//         public static extern bool WinDivertHelperParseIPv4Address([In] [MarshalAs(UnmanagedType.LPStr)] string addrStr, IntPtr pAddr);

//         /// Return Type: BOOL->int
//         ///addrStr: char*
//         ///pAddr: UINT32*
//         [DllImport(dllPath, EntryPoint = "WinDivertHelperParseIPv6Address", SetLastError = true)]
//         [return: MarshalAs(UnmanagedType.Bool)]
//         public static extern bool WinDivertHelperParseIPv6Address([In] [MarshalAs(UnmanagedType.LPStr)] string addrStr, IntPtr pAddr);

        /// Return Type: UINT->unsigned int
        ///pPacket: PVOID->void*
        ///packetLen: UINT->unsigned int
        ///pAddr: PWINDIVERT_ADDRESS
        ///flags: UINT64->unsigned __int64
        [DllImport(dllPath, EntryPoint = "WinDivertHelperCalcChecksums", SetLastError = true)]
        public static unsafe extern uint WinDivertHelperCalcChecksums(byte[] pPacket, uint packetLen, ref WINDIVERT_ADDRESS pAddr, ulong flags);

//         /// Return Type: BOOL->int
//         ///filter: char*
//         ///layer: WINDIVERT_LAYER->Anonymous_d7dac89f_91f7_4aca_b997_239f157c8039
//         ///errorStr: char**
//         ///errorPos: UINT*
//         [DllImport(dllPath, EntryPoint = "WinDivertHelperCheckFilter", SetLastError = true)]
//         [return: MarshalAs(UnmanagedType.Bool)]
//         public static extern bool WinDivertHelperCheckFilter([In] [MarshalAs(UnmanagedType.LPStr)] string filter, WINDIVERT_LAYER layer, ref IntPtr errorStr, IntPtr errorPos);

//         /// Return Type: BOOL->int
//         ///filter: char*
//         ///layer: WINDIVERT_LAYER->Anonymous_d7dac89f_91f7_4aca_b997_239f157c8039
//         ///pPacket: PVOID->void*
//         ///packetLen: UINT->unsigned int
//         ///pAddr: PWINDIVERT_ADDRESS->Anonymous_7d42ad21_898e_4fdf_a30d_dc1e2c77a38f*
//         [DllImport(dllPath, EntryPoint = "WinDivertHelperEvalFilter", SetLastError = true)]
//         [return: MarshalAs(UnmanagedType.Bool)]
//         public static extern bool WinDivertHelperEvalFilter([In] [MarshalAs(UnmanagedType.LPStr)] string filter, WINDIVERT_LAYER layer, [In] byte[] pPacket, uint packetLen, [In] ref WINDIVERT_ADDRESS pAddr);
    }
}