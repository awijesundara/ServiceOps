"""Project management records (B-443): projects, their members and
statuses, and work items with assignees, watchers, labels, comments,
history and links.

Every table carries tenant_id; every query goes through
serviceops_core.projects.service, which scopes it to the tenant and to the
projects the user may see.
"""
from serviceops_models import db, now, tenant_context_id

PROJECT_ROLES = ("admin", "member", "viewer")
VISIBILITIES = ("private", "open")
STATUS_CATEGORIES = ("todo", "in_progress", "done")
ITEM_TYPES = ("epic", "story", "task", "bug", "subtask")
PRIORITIES = ("highest", "high", "medium", "low", "lowest")
LINK_TYPES = ("blocks", "relates", "duplicates")  # phase 1 names; WorkItemLinkType holds the full set
DEFAULT_LINK_TYPES = (  # (name, outward, inward) as in Jira
    ("blocks", "blocks", "is blocked by"),
    ("clones", "clones", "is cloned by"),
    ("duplicates", "duplicates", "is duplicated by"),
    ("relates", "relates to", "relates to"),
    ("causes", "causes", "is caused by"),
)
DEFAULT_RESOLUTIONS = (("Done", "Work has been completed."), ("Won't do", "This will not be worked on."),
                       ("Duplicate", "The problem is a duplicate of an existing work item."),
                       ("Cannot reproduce", "The problem could not be reproduced."))
DEFAULT_ASSIGNEE_CHOICES = ("unassigned", "project_lead")
COMPONENT_ASSIGNEE_CHOICES = ("project_default", "component_lead", "project_lead", "unassigned")
COMMENT_VISIBILITY = (None, "admin", "member")  # None: everyone who can see the work item
REACTIONS = ("👍", "👎", "😄", "🎉", "❤️", "👀")
DEFAULT_STATUSES = (("To do", "todo"), ("In progress", "in_progress"), ("In review", "in_progress"), ("Done", "done"))


def _tenant_column():
    return db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False, default=tenant_context_id, index=True)


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = _tenant_column()
    key = db.Column(db.String(10), nullable=False)
    name = db.Column(db.String(160), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    lead_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    color = db.Column(db.String(7), nullable=False, default="#0f6e7a")
    visibility = db.Column(db.String(10), nullable=False, default="private")
    # Next work item number; taken under a row lock so numbers never repeat.
    next_number = db.Column(db.Integer, nullable=False, default=1)
    archived_at = db.Column(db.DateTime(timezone=True))
    category = db.Column(db.String(60))
    # Who new work items go to when nobody is chosen (Jira's default assignee).
    default_assignee = db.Column(db.String(20), nullable=False, default="unassigned", server_default="unassigned")
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now, onupdate=now)
    lead = db.relationship("User", foreign_keys=[lead_id])
    statuses = db.relationship("ProjectStatus", order_by="ProjectStatus.position", cascade="all, delete-orphan",
                               back_populates="project")
    members = db.relationship("ProjectMember", cascade="all, delete-orphan", back_populates="project")
    __table_args__ = (db.UniqueConstraint("tenant_id", "key", name="uq_project_tenant_key"),)


class ProjectMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = _tenant_column()
    project_id = db.Column(db.Integer, db.ForeignKey("project.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    role = db.Column(db.String(10), nullable=False, default="member")
    added_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now)
    project = db.relationship("Project", back_populates="members")
    user = db.relationship("User")
    __table_args__ = (db.UniqueConstraint("project_id", "user_id", name="uq_project_member_user"),)


class ProjectStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = _tenant_column()
    project_id = db.Column(db.Integer, db.ForeignKey("project.id", ondelete="CASCADE"), nullable=False, index=True)
    name = db.Column(db.String(60), nullable=False)
    category = db.Column(db.String(12), nullable=False, default="todo")
    position = db.Column(db.Integer, nullable=False, default=0)
    # Board column limit; None means no limit.
    wip_limit = db.Column(db.Integer)
    project = db.relationship("Project", back_populates="statuses")
    __table_args__ = (db.UniqueConstraint("project_id", "name", name="uq_project_status_name"),)


class WorkItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = _tenant_column()
    project_id = db.Column(db.Integer, db.ForeignKey("project.id", ondelete="CASCADE"), nullable=False)
    number = db.Column(db.Integer, nullable=False)
    item_type = db.Column(db.String(10), nullable=False, default="task")
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    status_id = db.Column(db.Integer, db.ForeignKey("project_status.id"), nullable=False)
    priority = db.Column(db.String(10), nullable=False, default="medium")
    reporter_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    parent_id = db.Column(db.Integer, db.ForeignKey("work_item.id", ondelete="SET NULL"), index=True)
    # Order in the backlog and within a board column (smaller first).
    rank = db.Column(db.Float, nullable=False, default=0.0)
    start_date = db.Column(db.Date)
    due_date = db.Column(db.Date, index=True)
    story_points = db.Column(db.Float)
    estimate_minutes = db.Column(db.Integer)  # original estimate
    remaining_minutes = db.Column(db.Integer)
    spent_minutes = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    environment = db.Column(db.Text, nullable=False, default="", server_default="")
    resolution_id = db.Column(db.Integer, db.ForeignKey("work_item_resolution.id"))
    flagged = db.Column(db.Boolean, nullable=False, default=False, server_default=db.false())
    resolved_at = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now, onupdate=now)
    project = db.relationship("Project")
    status = db.relationship("ProjectStatus")
    reporter = db.relationship("User", foreign_keys=[reporter_id])
    parent = db.relationship("WorkItem", remote_side=[id], backref="children")
    assignees = db.relationship("User", secondary="work_item_assignee", lazy="selectin", order_by="User.name")
    labels = db.relationship("WorkItemLabel", lazy="selectin", cascade="all, delete-orphan",
                             order_by="WorkItemLabel.label")
    resolution = db.relationship("WorkItemResolution")
    components = db.relationship("ProjectComponent", secondary="work_item_component", lazy="selectin",
                                 order_by="ProjectComponent.name")
    fix_versions = db.relationship("ProjectVersion", secondary="work_item_fix_version", lazy="selectin",
                                   order_by="ProjectVersion.position")
    affects_versions = db.relationship("ProjectVersion", secondary="work_item_affects_version", lazy="selectin",
                                       order_by="ProjectVersion.position")
    __table_args__ = (
        db.UniqueConstraint("project_id", "number", name="uq_work_item_project_number"),
        db.Index("ix_work_item_project_status_rank", "project_id", "status_id", "rank"),
    )

    @property
    def key(self):
        return f"{self.project.key}-{self.number}"


class WorkItemAssignee(db.Model):
    work_item_id = db.Column(db.Integer, db.ForeignKey("work_item.id", ondelete="CASCADE"), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), primary_key=True, index=True)
    tenant_id = _tenant_column()


class WorkItemWatcher(db.Model):
    work_item_id = db.Column(db.Integer, db.ForeignKey("work_item.id", ondelete="CASCADE"), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), primary_key=True, index=True)
    tenant_id = _tenant_column()


class WorkItemLabel(db.Model):
    work_item_id = db.Column(db.Integer, db.ForeignKey("work_item.id", ondelete="CASCADE"), primary_key=True)
    label = db.Column(db.String(60), primary_key=True)
    tenant_id = _tenant_column()


class WorkItemComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = _tenant_column()
    work_item_id = db.Column(db.Integer, db.ForeignKey("work_item.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    body = db.Column(db.Text, nullable=False)
    # Restrict to a project role ("admin" or "member"); None: everyone who can see the item.
    visibility = db.Column(db.String(10))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now)
    edited_at = db.Column(db.DateTime(timezone=True))
    author = db.relationship("User")


class WorkItemHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = _tenant_column()
    work_item_id = db.Column(db.Integer, db.ForeignKey("work_item.id", ondelete="CASCADE"), nullable=False, index=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    field = db.Column(db.String(40), nullable=False)
    old_value = db.Column(db.Text)
    new_value = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now)
    actor = db.relationship("User")


class WorkItemLink(db.Model):
    """A link from a work item to another work item or to an ITSM record
    (target_type "ticket" for incidents and changes, "enterprise" for
    problems). For "blocks", the source blocks the target."""
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = _tenant_column()
    source_id = db.Column(db.Integer, db.ForeignKey("work_item.id", ondelete="CASCADE"), nullable=False, index=True)
    link_type = db.Column(db.String(12), nullable=False, default="relates")
    target_type = db.Column(db.String(12), nullable=False, default="work_item")
    target_id = db.Column(db.Integer, nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now)
    __table_args__ = (
        db.UniqueConstraint("source_id", "link_type", "target_type", "target_id", name="uq_work_item_link"),
        db.Index("ix_work_item_link_target", "target_type", "target_id"),
    )


class WorkItemResolution(db.Model):
    """Why a work item reached a done status (Jira's resolution), per tenant."""
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = _tenant_column()
    name = db.Column(db.String(60), nullable=False)
    description = db.Column(db.String(255), nullable=False, default="")
    position = db.Column(db.Integer, nullable=False, default=0)
    is_default = db.Column(db.Boolean, nullable=False, default=False)
    __table_args__ = (db.UniqueConstraint("tenant_id", "name", name="uq_work_item_resolution_name"),)


class WorkItemLinkType(db.Model):
    """A named link with its outward and inward wording, per tenant."""
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = _tenant_column()
    name = db.Column(db.String(40), nullable=False)
    outward = db.Column(db.String(60), nullable=False)
    inward = db.Column(db.String(60), nullable=False)
    __table_args__ = (db.UniqueConstraint("tenant_id", "name", name="uq_work_item_link_type_name"),)


class ProjectComponent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = _tenant_column()
    project_id = db.Column(db.Integer, db.ForeignKey("project.id", ondelete="CASCADE"), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    lead_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    default_assignee = db.Column(db.String(20), nullable=False, default="project_default")
    lead = db.relationship("User")
    __table_args__ = (db.UniqueConstraint("project_id", "name", name="uq_project_component_name"),)


class ProjectVersion(db.Model):
    """A release (Jira's version)."""
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = _tenant_column()
    project_id = db.Column(db.Integer, db.ForeignKey("project.id", ondelete="CASCADE"), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    start_date = db.Column(db.Date)
    release_date = db.Column(db.Date)
    released = db.Column(db.Boolean, nullable=False, default=False)
    released_at = db.Column(db.DateTime(timezone=True))
    archived = db.Column(db.Boolean, nullable=False, default=False)
    position = db.Column(db.Integer, nullable=False, default=0)
    __table_args__ = (db.UniqueConstraint("project_id", "name", name="uq_project_version_name"),)


class WorkItemComponent(db.Model):
    work_item_id = db.Column(db.Integer, db.ForeignKey("work_item.id", ondelete="CASCADE"), primary_key=True)
    component_id = db.Column(db.Integer, db.ForeignKey("project_component.id", ondelete="CASCADE"),
                             primary_key=True, index=True)
    tenant_id = _tenant_column()


class WorkItemFixVersion(db.Model):
    work_item_id = db.Column(db.Integer, db.ForeignKey("work_item.id", ondelete="CASCADE"), primary_key=True)
    version_id = db.Column(db.Integer, db.ForeignKey("project_version.id", ondelete="CASCADE"),
                           primary_key=True, index=True)
    tenant_id = _tenant_column()


class WorkItemAffectsVersion(db.Model):
    work_item_id = db.Column(db.Integer, db.ForeignKey("work_item.id", ondelete="CASCADE"), primary_key=True)
    version_id = db.Column(db.Integer, db.ForeignKey("project_version.id", ondelete="CASCADE"),
                           primary_key=True, index=True)
    tenant_id = _tenant_column()


class WorkItemWorklog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = _tenant_column()
    work_item_id = db.Column(db.Integer, db.ForeignKey("work_item.id", ondelete="CASCADE"), nullable=False, index=True)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    started_at = db.Column(db.DateTime(timezone=True), nullable=False)
    minutes = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=False, default="")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now)
    updated_at = db.Column(db.DateTime(timezone=True))
    author = db.relationship("User")


class WorkItemVote(db.Model):
    work_item_id = db.Column(db.Integer, db.ForeignKey("work_item.id", ondelete="CASCADE"), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), primary_key=True, index=True)
    tenant_id = _tenant_column()
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now)


class ProjectStar(db.Model):
    """A user's starred project or work item (target_type "project" or "work_item")."""
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), primary_key=True)
    target_type = db.Column(db.String(12), primary_key=True)
    target_id = db.Column(db.Integer, primary_key=True)
    tenant_id = _tenant_column()
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now)


class WorkItemView(db.Model):
    """When a user last opened a work item (Your work → Viewed)."""
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), primary_key=True)
    work_item_id = db.Column(db.Integer, db.ForeignKey("work_item.id", ondelete="CASCADE"), primary_key=True)
    tenant_id = _tenant_column()
    viewed_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now, index=True)


class WorkItemCommentReaction(db.Model):
    comment_id = db.Column(db.Integer, db.ForeignKey("work_item_comment.id", ondelete="CASCADE"), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), primary_key=True)
    emoji = db.Column(db.String(16), primary_key=True)
    tenant_id = _tenant_column()


class WorkItemKeyAlias(db.Model):
    """A key a work item had before it moved to another project, so old
    links keep working (Jira redirects moved keys)."""
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = _tenant_column()
    project_key = db.Column(db.String(10), nullable=False)
    number = db.Column(db.Integer, nullable=False)
    work_item_id = db.Column(db.Integer, db.ForeignKey("work_item.id", ondelete="CASCADE"), nullable=False)
    __table_args__ = (db.UniqueConstraint("tenant_id", "project_key", "number", name="uq_work_item_key_alias"),)


MODEL_NAMES = [
    "Project", "ProjectMember", "ProjectStatus", "WorkItem", "WorkItemAssignee", "WorkItemWatcher",
    "WorkItemLabel", "WorkItemComment", "WorkItemHistory", "WorkItemLink",
    "WorkItemResolution", "WorkItemLinkType", "ProjectComponent", "ProjectVersion", "WorkItemComponent",
    "WorkItemFixVersion", "WorkItemAffectsVersion", "WorkItemWorklog", "WorkItemVote", "ProjectStar",
    "WorkItemView", "WorkItemCommentReaction", "WorkItemKeyAlias",
]
