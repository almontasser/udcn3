use std::time::Duration;

pub fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    let millis = duration.subsec_millis();
    let micros = duration.subsec_micros() % 1000;
    
    if secs > 0 {
        format!("{}.{:03}s", secs, millis)
    } else if millis > 0 {
        format!("{}.{:03}ms", millis, micros)
    } else {
        format!("{}μs", duration.as_micros())
    }
}

pub fn format_throughput(ops_per_sec: f64) -> String {
    if ops_per_sec >= 1_000_000.0 {
        format!("{:.2}M ops/sec", ops_per_sec / 1_000_000.0)
    } else if ops_per_sec >= 1_000.0 {
        format!("{:.2}K ops/sec", ops_per_sec / 1_000.0)
    } else {
        format!("{:.2} ops/sec", ops_per_sec)
    }
}

pub fn percentile(values: &mut [Duration], percentile: f64) -> Duration {
    if values.is_empty() {
        return Duration::from_secs(0);
    }
    
    values.sort();
    let index = (values.len() as f64 * percentile / 100.0) as usize;
    let index = index.min(values.len() - 1);
    values[index]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_secs(1)), "1.000s");
        assert_eq!(format_duration(Duration::from_millis(500)), "500.000ms");
        assert_eq!(format_duration(Duration::from_micros(100)), "100μs");
    }

    #[test]
    fn test_format_throughput() {
        assert_eq!(format_throughput(1_500_000.0), "1.50M ops/sec");
        assert_eq!(format_throughput(1_500.0), "1.50K ops/sec");
        assert_eq!(format_throughput(15.0), "15.00 ops/sec");
    }

    #[test]
    fn test_percentile() {
        let mut values = vec![
            Duration::from_millis(1),
            Duration::from_millis(2),
            Duration::from_millis(3),
            Duration::from_millis(4),
            Duration::from_millis(5),
        ];
        
        assert_eq!(percentile(&mut values, 50.0), Duration::from_millis(3));
        assert_eq!(percentile(&mut values, 90.0), Duration::from_millis(5));
    }
}