using System;
using System.Text.Json;

namespace SlimAtp
{
    public class ListRequestOptions
    {
        public string? Select { get; set; }
        public string? Filter { get; set; }
        public string? Search { get; set; }
        public string? Expand { get; set; }
        public string? OrderBy { get; set; }
        public bool? Count { get; set; }
        public int? Skip { get; set; }
        public int? Top { get; set; }
        public bool ConsistencyLevelEventual { get; set; }

        public event EventHandler<JsonEventArgs>? PageReceived;

        internal void OnPageReceived(JsonElement element)
        {
            PageReceived?.Invoke(this, new JsonEventArgs(element));
        }
    }
}