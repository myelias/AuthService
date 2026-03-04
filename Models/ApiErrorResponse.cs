public class ApiErrorResponse
    {
        public string Error { get; set; } = string.Empty;

        public string? Details { get; set; }

        public string? Code { get; set; }

        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }