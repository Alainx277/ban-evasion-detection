public record User
{
	public int UserId { get; init; }
	public bool Banned { get; init; }

	public virtual bool Equals(User? other)
	{
		if (ReferenceEquals(this, other)) return true;
		if (other is null) return false;
		return UserId == other.UserId;
	}

	public override int GetHashCode() => UserId;
}
