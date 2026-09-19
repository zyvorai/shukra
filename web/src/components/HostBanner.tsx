export default function HostBanner() {
  return (
    <p className="host-banner" role="note">
      These connections are from the QEMU process, not the guest. guest_attributed is false. Tap/TCX attribution is not attached.
    </p>
  );
}
