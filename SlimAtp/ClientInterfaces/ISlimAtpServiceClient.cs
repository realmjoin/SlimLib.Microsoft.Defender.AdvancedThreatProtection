namespace SlimAtp
{
    public interface ISlimAtpClient
    {
        ISlimAtpMachinesClient Devices { get; }
    }
}