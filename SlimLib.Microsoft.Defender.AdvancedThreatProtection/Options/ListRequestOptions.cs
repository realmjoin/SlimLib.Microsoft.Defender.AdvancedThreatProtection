﻿using System;
using System.Collections.Generic;
using System.Text.Json;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection
{
    public class ListRequestOptions
    {
        public ListRequestOptions()
        {
        }

        public ListRequestOptions(EventHandler<MetadataEventArgs> handler) : this()
        {
            if (handler is null) throw new ArgumentNullException(nameof(handler));

            ConsistencyLevelEventual = true;
            Count = true;
            MetadataReceived = handler;
        }

        public HashSet<string> Select { get; } = new();
        public string? Filter { get; set; }
        public string? Search { get; set; }
        public string? Expand { get; set; }
        public HashSet<string> OrderBy { get; } = new();
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