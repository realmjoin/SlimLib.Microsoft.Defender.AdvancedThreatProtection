using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace SlimAtp.Auth
{
    public class AuthErrorResponse : AuthResponse
    {
        [JsonPropertyName("error")]
        public string? Error { get; set; }

        [JsonPropertyName("error_description")]
        public string? ErrorDescription { get; set; }

        [JsonPropertyName("error_codes")]
        public List<int>? ErrorCodes { get; set; }

        [JsonPropertyName("timestamp")]
        public string? Timestamp { get; set; }

        [JsonPropertyName("trace_id")]
        public string? TraceID { get; set; }

        [JsonPropertyName("correlation_id")]
        public string? CorrelationID { get; set; }
    }
}
