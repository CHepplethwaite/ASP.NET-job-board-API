using backend.Core.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace backend.Infrastructure.Data
{
    public class ApplicationDbContext : IdentityDbContext<User, Role, string,
        IdentityUserClaim<string>, UserRole, IdentityUserLogin<string>,
        IdentityRoleClaim<string>, IdentityUserToken<string>>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<JobSeekerProfile> JobSeekerProfiles { get; set; }
        public DbSet<RecruiterProfile> RecruiterProfiles { get; set; }
        public DbSet<CompanyProfile> CompanyProfiles { get; set; }
        public DbSet<ExternalLogin> ExternalLogins { get; set; }
        public DbSet<WorkExperience> WorkExperiences { get; set; }
        public DbSet<Education> Educations { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // Configure UserRole
            builder.Entity<UserRole>(entity =>
            {
                entity.HasKey(ur => new { ur.UserId, ur.RoleId });

                entity.HasOne(ur => ur.User)
                    .WithMany(u => u.UserRoles)
                    .HasForeignKey(ur => ur.UserId)
                    .IsRequired();

                entity.HasOne(ur => ur.Role)
                    .WithMany(r => r.UserRoles)
                    .HasForeignKey(ur => ur.RoleId)
                    .IsRequired();
            });

            // Configure User
            builder.Entity<User>(entity =>
            {
                entity.Property(u => u.UserType)
                    .HasConversion<string>()
                    .HasMaxLength(20);

                entity.HasOne(u => u.JobSeekerProfile)
                    .WithOne(j => j.User)
                    .HasForeignKey<JobSeekerProfile>(j => j.UserId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasOne(u => u.RecruiterProfile)
                    .WithOne(r => r.User)
                    .HasForeignKey<RecruiterProfile>(r => r.UserId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasOne(u => u.CompanyProfile)
                    .WithOne(c => c.User)
                    .HasForeignKey<CompanyProfile>(c => c.UserId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasMany(u => u.ExternalLogins)
                    .WithOne(el => el.User)
                    .HasForeignKey(el => el.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            // Configure JobSeekerProfile
            builder.Entity<JobSeekerProfile>(entity =>
            {
                entity.HasMany(j => j.WorkExperiences)
                    .WithOne(w => w.JobSeekerProfile)
                    .HasForeignKey(w => w.JobSeekerProfileId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasMany(j => j.Educations)
                    .WithOne(e => e.JobSeekerProfile)
                    .HasForeignKey(e => e.JobSeekerProfileId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            // Configure RecruiterProfile
            builder.Entity<RecruiterProfile>(entity =>
            {
                entity.HasOne(r => r.Company)
                    .WithMany(c => c.Recruiters)
                    .HasForeignKey(r => r.CompanyId)
                    .OnDelete(DeleteBehavior.SetNull);
            });
        }
    }
}