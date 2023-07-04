using System.Collections.Generic;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection
{
    public class ScalarRequestOptions
    {
        public HashSet<string> Select { get; } = new();
        public string? Expand { get; set; }
    }
}