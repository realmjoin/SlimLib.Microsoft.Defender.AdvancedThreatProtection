using System;
using System.Text.Json;

namespace SlimAtp
{
    public class ListRequestOptions
    {
        public ListRequestOptions(EventHandler<MetadataEventArgs> handler)
        {
            if (handler is null) throw new ArgumentNullException(nameof(handler));

            ConsistencyLevelEventual = true;
            Count = true;
            MetadataReceived = handler;
        }

        public string? Select { get; set; }
        public string? Filter { get; set; }
        public string? Search { get; set; }
        public string? Expand { get; set; }
        public string? OrderBy { get; set; }
        public bool? Count { get; set; }
        public int? Skip { get; set; }
        public int? Top { get; set; }
        public int? MaxPageSize { get; set; }
        public bool ConsistencyLevelEventual { get; set; }

        public event EventHandler<MetadataEventArgs>? MetadataReceived;
        public event EventHandler<JsonEventArgs>? PageReceived;

        internal void OnMetadataReceived(JsonElement element)
        {
            if (MetadataReceived == null) return;

            var context = default(string?);
            var count = default(long?);

            if (element.TryGetProperty("@odata.context", out var contextEl) && contextEl.ValueKind == JsonValueKind.String)
            {
                context = contextEl.GetString();
            }

            if (element.TryGetProperty("@odata.count", out var countEl) && countEl.ValueKind == JsonValueKind.Number)
            {
                if (countEl.TryGetInt64(out var val))
                {
                    count = val;
                }
            }

            MetadataReceived?.Invoke(this, new MetadataEventArgs(context, count));
        }

        internal void OnPageReceived(JsonElement element)
        {
            PageReceived?.Invoke(this, new JsonEventArgs(element));
        }
    }
}