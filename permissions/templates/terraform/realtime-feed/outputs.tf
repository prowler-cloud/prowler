output "queue_url" {
  description = "Paste this URL in Prowler Cloud, Realtime, Real-time feed."
  value       = aws_sqs_queue.events.url
}
