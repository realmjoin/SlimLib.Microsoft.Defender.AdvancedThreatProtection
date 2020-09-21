namespace SlimAtp
{
    public interface ISlimAtpClient
    {
        ISlimAtpMachineClient Machine { get; }
        ISlimAtpSoftwareClient Software { get; }
    }
}