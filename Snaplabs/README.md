# SnapLabs ADCS Lab Setup (Configuration-Only)

This is a **configuration-only** walkthrough of how we built the ADCS lab in **Immersive Labs SnapLabs** starting from the **AD Quickstart** range, then using an **Ansible machine** to configure ADCS and the ESC templates, and finally applying the **manual fixes** we needed for **ESC8 (Web Enrollment /certsrv)** and **ESC4 (Template ACL)**.

**THIS IS ONLY IF YOU WANT TO CREATE YOUR OWN RANGE AND NOT USING THE TEMPLATE**

---

## 0) What you end up with

- A SnapLabs range created from **AD Quickstart**
- Windows hosts:
  - **DC**: `DC.snaplabs.local` (Domain Controller)
  - **CA**: `server.snaplabs.local` (ADCS + Web Enrollment)
- One Linux host:
  - **Ansible**: `ubuntu@10.10.0.49` (example), used to run the playbook
- ADCS configured using the Ansible role **badsectorlabs.ludus_adcs**
- Templates renamed and ESC-related misconfigs applied
- Manual fixes:
  - `/certsrv` published properly (ESC8 prereq)
  - Template ACL corrected for ESC4

---

## 1) Create the SnapLabs Range (AD Quickstart)

1. In SnapLabs, create a new Range.
2. Choose the template **AD Quickstart**.
3. Deploy the range.

The quickstart template brings up a working domain automatically. We kept the default domain:

- Domain (FQDN): `snaplabs.local`
- NetBIOS: `SNAPLABS`

---

## 2) Quick validation on the DC (optional but useful)

On the **Domain Controller**, confirm domain details:

```powershell
hostname
Get-ADDomain | Select DNSRoot, NetBIOSName
```

Expected:
- `DNSRoot` = `snaplabs.local`
- `NetBIOSName` = `SNAPLABS`

---

## 3) Create the Ansible machine (Linux)

Create a Linux VM (Ubuntu) inside the same SnapLabs range/subnet so it can reach the Windows hosts.

### 3.1 Install Ansible + WinRM dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-pip git
pip3 install --user ansible pywinrm
```

Make sure `ansible` and `python3` are available:

```bash
ansible --version
python3 -c "import winrm; print('pywinrm ok')"
```

---

## 3A) Prepare the CA server for Ansible (WinRM)

Ansible cannot manage Windows hosts unless **WinRM/PowerShell Remoting** is enabled. This is the #1 step people skip.

On `server.snaplabs.local` (future CA), RDP in and open **PowerShell as Administrator**, then run:

```powershell
winrm quickconfig -q

Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
Set-Item WSMan:\localhost\Service\Auth\CredSSP -Value $true
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true

Enable-PSRemoting -Force
```

(Optional but recommended) Enable the firewall rules for WinRM:

```powershell
Enable-NetFirewallRule -DisplayGroup "Windows Remote Management"
```

After this, the Ansible machine should be able to connect using `win_ping`.

## 4) Install the role via Ansible Galaxy (this is how we did it)

We installed it directly using Ansible Galaxy:

```bash
ansible-galaxy install badsectorlabs.ludus_adcs
```

Confirm it’s installed:

```bash
ansible-galaxy list | grep -i ludus_adcs
```

---

## 5) Final inventory.ini (working)

This is the **final inventory.ini** that worked:

```ini
[ca]
server.snaplabs.local ansible_host=10.10.0.47

[ca:vars]
ansible_connection=winrm
ansible_user=domain_admin@snaplabs.local
ansible_password=P@ssword1
ansible_port=5985
ansible_winrm_transport=ntlm
ansible_winrm_server_cert_validation=ignore
```

### 5.1 Connectivity test

```bash
ansible -i inventory.ini ca -m win_ping
```

If WinRM auth fails, SnapLabs often accepts **UPN format** (as shown above):
- ✅ `domain_admin@snaplabs.local` worked

---

## 6) Final site.yml (working)

This is the **final site.yml** used:

```yaml
- hosts: ca
  roles:
    - badsectorlabs.ludus_adcs

  vars:
    ludus_adcs_domain: "snaplabs.local"
    ludus_domain_netbios_name: "SNAPLABS"
    ludus_domain_fqdn_tail: "snaplabs.local"

    ludus_adcs_ca_host: server
    ludus_adcs_dc: "DC.snaplabs.local"

    ludus_adcs_domain_username: "domain_admin@snaplabs.local"
    ludus_adcs_domain_password: P@ssword1

    ludus_adcs_ca_common_name: SNAPLABS-CA
    ludus_adcs_ca_web_enrollment: true

    ludus_adcs_esc1: true
    ludus_adcs_esc2: true
    ludus_adcs_esc3: true
    ludus_adcs_esc3_cra: true
    ludus_adcs_esc4: true
    ludus_adcs_esc5: true
    ludus_adcs_esc6: true
    ludus_adcs_esc7: true
    ludus_adcs_esc8: true
    ludus_adcs_esc9: true
    ludus_adcs_esc11: true
    ludus_adcs_esc13: true
    ludus_adcs_esc15: true
    ludus_adcs_esc16: true

    # Rename templates (optional)
    ludus_adcs_template_display_names:
        ESC1: "WorkstationAuth"
        ESC2: "DocEncryption"
        ESC3: "EmployeeCert"
        ESC3_CRA: "EnrollmentAgent"
        ESC4: "LegacyApp"
        ESC7_CERTMGR: "Certmgr"
        ESC9: "ServerAuth"
        ESC13: "Smartcard"

    ludus:
    - hostname: DC
      domain:
        fqdn: snaplabs.local
        role: primary-dc

    - hostname: server
      domain:
        fqdn: snaplabs.local
        role: ca
```

### 6.1 Run the playbook

```bash
ansible-playbook -i inventory.ini site.yml
```

---

## 7) Fix for ESC5 task crash (SnapLabs-specific)

We also hit a broken command in the role trying to run:

```text
net localgroup S-1-5-32-544 ...
```

`net localgroup` does **not** accept a SID as a group name, so it fails on member servers (like the CA). We resolved this by **skipping** that ESC5 sub-step in the role when needed (the rest of the lab config still completes).

Fix task esc5.yml

```bash
cat ~/.ansible/roles/badsectorlabs.ludus_adcs/tasks/esc5.yml 
---
- name: Display Primary DC and CA host
  ansible.builtin.debug:
    msg: "DC: {{ ludus_adcs_dc }} | CA: {{ ludus_adcs_ca_host }}"

- name: Create an ESC5 domain user
  microsoft.ad.user:
    name: "{{ ludus_adcs_esc5_user }}"
    password: "{{ ludus_adcs_esc5_password }}"
    upn: "{{ ludus_adcs_esc5_user }}"
    password_never_expires: true
    user_cannot_change_password: true
    state: present
    domain_username: "{{ ludus_adcs_domain_username }}"
    domain_password: "{{ ludus_adcs_domain_password }}"
    domain_server: "{{ ludus_adcs_dc }}"

- name: Check if user is already in the Administrators group
  ansible.windows.win_shell: |
    if ((Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4) { (net group "$((Get-ADGroup -Identity "$((Get-ADDomain).DomainSID)-512").Name)" /domain | Select-String -Pattern '{{ lu
dus_adcs_esc5_user }}') -ne $null } else { (net localgroup Administrators | Select-String -Pattern '{{ ludus_adcs_esc5_user }}') -ne $null }
  register: user_is_admin
  args:
    executable: powershell

- name: Add ESC5 user to local administrators group
  ansible.windows.win_shell: |
    if ((Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4) { net group "$((Get-ADGroup -Identity "$((Get-ADDomain).DomainSID)-512").Name)" '{{ ludus_adcs_esc5_user }}' /add /domai
n } else { net localgroup Administrators /add '{{ ludus_adcs_esc5_user }}' }
  become: true
  become_method: runas
  vars:
    ansible_become: true
    ansible_become_method: runas
    domain_name: "{{ ludus_adcs_domain }}"
    ansible_become_user: "{{ ludus_adcs_domain_username }}"
    ansible_become_password: "{{ ludus_adcs_domain_password }}"
  when: user_is_admin.stdout == "False\r\n"
  register: esc5_output

- name: Output ESC5 script result
  ansible.builtin.debug:
    var: esc5_output
```

---

## 8) ESC8 prereq fix: /certsrv returning 404 (Web Enrollment published but missing vdir)

### 8.1 Symptom

From attacker/any host:

```bash
curl -I http://server.snaplabs.local/certsrv/
```

We initially got:

- `HTTP/1.1 404 Not Found`

Even though the feature was installed:

```powershell
Get-WindowsFeature ADCS-Web-Enrollment
```

And the files existed:

```powershell
Test-Path C:\Windows\System32\CertSrv
# True
```

### 8.2 Fix we applied

On the **CA**, this command fixed the `/certsrv` publication:

```powershell
certutil -vroot
```

Then restart IIS:

```powershell
iisreset
```

Re-test:

```bash
curl -I http://server.snaplabs.local/certsrv/
```

Expected after fix:
- not a 404 anymore (you should at least see an auth challenge/response instead of Not Found)

### 8.3 Validate in IIS Manager (optional)

On the CA:

```powershell
inetmgr
```

Confirm under **Default Web Site** that **CertSrv** exists and authentication is configured (Windows auth enabled, anonymous disabled) if you want the classic behavior.

---

## 9) ESC4 fix: Template ACL was not actually vulnerable

### 9.1 Symptom

The template existed (renamed to `LegacyApp`) but it wasn’t effectively misconfigured for ESC4.

### 9.2 Manual PowerShell fix that worked

We applied the ACL change directly in AD (Certificate Templates container). This script worked:

```powershell
Import-Module ActiveDirectory

$template = "LegacyApp"
$principal = "SNAPLABS\Domain Users"

$dn = "CN=$template,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=snaplabs,DC=local"

$acl = Get-Acl "AD:$dn"

$sid = (New-Object System.Security.Principal.NTAccount($principal)).Translate([System.Security.Principal.SecurityIdentifier])

$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
    $sid,
    "GenericAll",
    "Allow"

$acl.AddAccessRule($rule)
Set-Acl -AclObject $acl -Path "AD:$dn"
```

**Note:** If you see `Cannot find drive. A drive with the name 'AD' does not exist`, ensure you run:

```powershell
Import-Module ActiveDirectory
Set-Location AD:
```

(or run the script in a session where the ActiveDirectory PSDrive is available).

---

## 10) Final checkpoints (configuration)

On the CA:

- ADCS installed and CA online
- Web Enrollment reachable at `/certsrv` (no 404)
- Templates are published/issued in:
  - `certsrv.msc` → **Certificate Templates**
- ESC4 template ACL corrected via the PowerShell script above

---

## Appendix: Commands we used a lot

### Ansible side

```bash
ansible-galaxy install badsectorlabs.ludus_adcs
ansible -i inventory.ini ca -m win_ping
ansible-playbook -i inventory.ini site.yml
```

### Windows side (DC/CA)

```powershell
hostname
Get-ADDomain | Select DNSRoot, NetBIOSName
Get-WindowsFeature ADCS-Web-Enrollment
Test-Path C:\Windows\System32\CertSrv
inetmgr
certsrv.msc
certutil -vroot
iisreset
```
