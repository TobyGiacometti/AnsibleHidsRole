# Ansible HIDS Role

An [Ansible][1] role that manages a host-based intrusion detection system.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
    - [Variables](#variables)
    - [Agent Registration](#agent-registration)
    - [RESTful Manager API](#restful-manager-api)
    - [Example](#example)

## Features

- Sets up a HIDS powered by [Wazuh][2].
- Streamlines the setup by installing the minimum amount of components necessary (*no* web-based GUI or visualization tools).
- Enables easy configuration of every aspect of the HIDS.
- Automates management of agent authentication keys.

## Requirements

- Debian GNU/Linux 10 (Buster) on managed host

## Installation

Use [Ansible Galaxy][3] to install `tobygiacometti.hids`. Check out the Ansible Galaxy [content installation instructions][4] if you need help.

## Usage

To get general guidance on how to use Ansible roles, visit the [official documentation][5].

### Variables

- `hids_host_role`: Role of the managed host in the HIDS, either `manager` or `agent`. A manager is responsible for analyzing data sent by agents and responding appropriately when a threat is detected. In addition, managers also monitor themselves for issues. An agent, on the other hand, gathers the required data, sends it to a manager and executes any operations the manager requests.
- `hids_agent_name` *(agent only)*: Name of the agent. The name needs to be unique since it is used to identify the agent in the HIDS.
- `hids_manager` *(agent only)*: Manager to which the agent should send the gathered data. Please note that the Ansible inventory name of the manager must be used.
- `hids_rules` *(manager only)*: Additional rules for the HIDS. This variable takes a dictionary whose key-value pairs map directly to the [Wazuh rule labels][6] (check the [example][7] for details).
- `hids_config`: Configuration for the manager or agent. This variable takes a dictionary whose key-value pairs map directly to the [Wazuh configuration sections and options][8] (check the [example][7] for details). In addition, the top-level key `api` can be used to [configure the RESTful manager API][9].

### Agent Registration

This role takes care of registering agents with the manager. During this process an agent authentication key is securely retrieved (SSH) from the manager and installed on the agent. In addition, the manager's hostname is automatically set in the agent configuration. Keep in mind that agents need to be able to resolve the manager's hostname to an accessible IP address. If, for whatever reason, such a setup is not possible, you can [manually set the manager address][10] using the `hids_config` dictionary.

Agents that are not managed by this role will need to be registered with the manager as described in the [Wazuh documentation][11]. Please note that the authentication daemon (used for automatic agent-initiated registration) is disabled by this role for security reasons. To enable it, configure the [`auth` section][12] using the `hids_config` dictionary.

### RESTful Manager API

If needed, the manager can be controlled using a [RESTful API][13]. By default, the API only listens for connections on `127.0.0.1`. To allow external access, configure the API using the `hids_config` dictionary. Please note that this role generates a secure password for the API users (`wazuh` and `wazuh-wui`) during setup and stores it in the file `/root/wazuh-api-password`.

### Example

```yaml
- hosts: hids.domain.example
  roles:
    - role: tobygiacometti.hids
      vars:
        hids_host_role: manager
        hids_rules:
          # The content generation rules for hids_config apply here as well.
          group name="ossec,":
            rule id="554" level="7" overwrite="yes":
              category: ossec
              decoded_as: syscheck_new_entry
              description: File added to the system.
              group: syscheck,syscheck_entry_added,syscheck_file,pci_dss_11.5,gpg13_4.11,gdpr_II_5.1.f,hipaa_164.312.c.1,hipaa_164.312.c.2,nist_800_53_SI.7,tsc_PI1.4,tsc_PI1.5,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,
        hids_config:
          global:
            email_notification: "yes"
            smtp_server: localhost
            # Use a list of strings/numbers whenever an option needs to be repeated.
            email_to:
              - user1@domain.example
              - user2@domain.example
          email_alerts:
            email_to: user3@domain.example
            level: 12
            group: sshd,
            # Use a truthy value whenever an option without value needs to be set.
            do_not_delay: true

- hosts: hids_agents
  roles:
    - role: tobygiacometti.hids
      vars:
        hids_host_role: agent
        hids_agent_name: "{{ inventory_hostname }}"
        hids_manager: hids.domain.example
        hids_config:
          # Use a list of dictionaries whenever a section needs to be repeated.
          localfile:
            - log_format: syslog
              location: /var/log/syslog

            - log_format: command
              command: df -P
              frequency: 360
          labels:
            # Attributes for an option must be directly embedded in the dictionary key.
            label key="network.ip": 10.0.1.0
```

[1]: https://www.ansible.com
[2]: https://www.wazuh.com
[3]: https://galaxy.ansible.com
[4]: https://galaxy.ansible.com/docs/using/installing.html
[5]: https://docs.ansible.com/ansible/latest/user_guide/playbooks_reuse_roles.html
[6]: https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html
[7]: #example
[8]: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/index.html
[9]: https://documentation.wazuh.com/current/user-manual/api/configuration.html
[10]: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/client.html#address
[11]: https://documentation.wazuh.com/current/user-manual/registering/index.html
[12]: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/auth.html
[13]: https://documentation.wazuh.com/current/user-manual/api/index.html
