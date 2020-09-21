namespace SlimAtp
{
    public class RequestHeaderOptions
    {
        public ReturnOptions Return { get; set; }
        public bool ConsistencyLevelEventual { get; set; }
        public int? MaxPageSize { get; set; }
    }
}