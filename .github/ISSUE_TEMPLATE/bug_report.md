name: Bug report
about: Create a report to help us fix a profiler bug.
title: '[Bug]: '
labels: '["bug"]'
assignees: ''
body:
  - type: markdown
    attributes:
      value: |
        Thank you for taking the time to fill out this bug report!
  - type: textarea
    id: what-happened
    attributes:
      label: What happened?
      description: Also tell us, what did you expect to happen?
      placeholder: Tell us what happened and what you expected.
      value: "It's a bug"
    validations:
      required: true
  - type: textarea
    id: logs
    attributes:
      label: Relevant log output
      description: Please copy and paste any relevant log output. This will be automatically formatted into code, so no need for backticks.
      values: |
        * Run `$ sudo profiler --debug`, reproduce the issue, and paste in the full output.
        * Run `$ sudo profiler --list_interfaces`, and paste in the full output.
      render: shell
    validations:
      required: ture
  - type: checkboxes
    id: contribs
    attributes:
      label: Contributions
      description: By submitting this issue, you should review our [developer documentation](https://github.com/WLAN-Pi/developers).
      options:
        - label: I have read the contribution guidelines
          required: true
  - type: checkboxes
    id: terms
    attributes:
      label: Code of Conduct
      description: By submitting this issue, you agree to follow our [Code of Conduct](https://github.com/WLAN-Pi/.github/blob/main/code_of_conduct.md).
      options:
        - label: I agree to follow WLAN Pi's Code of Conduct
          required: true
