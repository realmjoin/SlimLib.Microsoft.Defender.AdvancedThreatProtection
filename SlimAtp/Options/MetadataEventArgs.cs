using System;

namespace SlimAtp
{
    public class MetadataEventArgs : EventArgs
    {
        public MetadataEventArgs(string? context, long? count)
        {
            Context = context;
            Count = count;
        }

        public string? Context { get; }
        public long? Count { get; }
    }
}