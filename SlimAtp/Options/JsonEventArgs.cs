using System;
using System.Text.Json;

namespace SlimAtp
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