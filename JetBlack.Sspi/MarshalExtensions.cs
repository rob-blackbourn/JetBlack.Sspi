using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace JetBlack.Sspi
{
    public static class MarshalExtensions
    {
        public static readonly DateTime Epoch = new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public static T ToStructure<T>(this IntPtr ptr)
        {
            return Marshal.PtrToStructure<T>(ptr);
        }

        public static IEnumerable<T> ToEnumerable<T>(this IntPtr ptr, int count)
        {
            var offset = ptr;
            for (var i = 0; i < count; ++i, offset += Marshal.SizeOf(typeof(T)))
                yield return Marshal.PtrToStructure<T>(offset);
        }

        public static DateTime ToDateTime(this long ticks)
        {
            return ticks > DateTime.MaxValue.ToFileTime() ? DateTime.MaxValue : DateTime.FromFileTime(ticks);
        }
    }
}
