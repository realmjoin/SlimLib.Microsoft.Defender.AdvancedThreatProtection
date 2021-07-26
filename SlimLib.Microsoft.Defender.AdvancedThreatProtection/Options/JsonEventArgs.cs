using System;
using System.Text.Json;

namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection
{
    public class JsonEventArgs : EventArgs
    {
        public JsonEventArgs(JsonElement element)
        {
            Element = element;
        }

        public JsonElement Element { get; }
    }
}