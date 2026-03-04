using Microsoft.EntityFrameworkCore;
using AuthService.Models;

namespace AuthService.Data;
public class UserDbContext : DbContext
{
    public UserDbContext(DbContextOptions<UserDbContext> options) : base(options)
    {
    }

    public DbSet<UserInfo> Users { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<UserInfo>()
            .HasKey(u => u.Id);

        modelBuilder.Entity<UserInfo>()
            .Property(u => u.Email)
            .IsRequired()
            .HasMaxLength(256);

        modelBuilder.Entity<UserInfo>()
            .Property(u => u.Name)
            .IsRequired()
            .HasMaxLength(100);

        modelBuilder.Entity<UserInfo>()
            .Property(u => u.Username)
            .IsRequired()
            .HasMaxLength(50);

        modelBuilder.Entity<UserInfo>()
            .Property(u => u.PasswordHash)
            .IsRequired()
            .HasMaxLength(256);
        
        modelBuilder.Entity<UserInfo>()
            .Property(u => u.LastLogin)
            .IsRequired();
    }
}