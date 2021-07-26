namespace SlimLib.Microsoft.Defender.AdvancedThreatProtection
{
    public interface ISlimAtpClient
    {
        ISlimAtpMachineClient Machine { get; }
        ISlimAtpUserClient User { get; }
        ISlimAtpSoftwareClient Software { get; }
    }
}