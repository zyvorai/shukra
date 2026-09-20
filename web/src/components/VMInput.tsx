/** A VM-name text field that suggests the VMs the daemon knows about. */
export default function VMInput({ value, names, onChange, label }: { value: string; names: string[]; onChange: (v: string) => void; label: string }) {
  return (
    <>
      <input value={value} onChange={(e) => onChange(e.target.value)} aria-label={label} list="shukra-vm-names" placeholder="VM name" />
      <datalist id="shukra-vm-names">
        {names.map((n) => (
          <option key={n} value={n} />
        ))}
      </datalist>
    </>
  );
}
