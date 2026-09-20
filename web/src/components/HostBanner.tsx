export default function HostBanner() {
  return (
    <p className="host-banner" role="note">
      These connections are from the QEMU process, not the guest, so guest_attributed is false. The guest's own connections, seen on its tap, are in the tables below when the tap program is attached.
    </p>
  );
}
